//! Parquet export pipeline. Writer handles live in a process-wide
//! registry so the FFI can stream rows from Swift across multiple
//! `pgFetchPage` calls without buffering the full result.
//!
//! All columns serialize as Utf8 — the explorer never has typed
//! values to begin with (everything comes back as the server's text
//! representation), and a Parquet file with text columns reads
//! correctly into every analysis tool that supports the format.
//! Per-OID Arrow type inference would be the polished v2; for v1,
//! "string Parquet that round-trips through pandas, DuckDB, and
//! Spark" is the right balance against the dep cost.

use std::collections::HashMap;
use std::fs::File;
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};

use arrow_array::{ArrayRef, RecordBatch, StringArray};
use arrow_schema::{DataType, Field, Schema};
use parquet::arrow::ArrowWriter;
use parquet::file::properties::WriterProperties;

#[derive(Debug, thiserror::Error)]
pub enum ParquetExportError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("arrow error: {0}")]
    Arrow(#[from] arrow_schema::ArrowError),
    #[error("parquet error: {0}")]
    Parquet(#[from] parquet::errors::ParquetError),
    #[error("unknown parquet writer id")]
    UnknownWriter,
}

struct ParquetExporter {
    writer: ArrowWriter<File>,
    schema: Arc<Schema>,
    column_count: usize,
}

impl ParquetExporter {
    fn create(path: &Path, columns: &[String]) -> Result<Self, ParquetExportError> {
        let fields = columns
            .iter()
            .map(|name| Field::new(name, DataType::Utf8, true))
            .collect::<Vec<_>>();
        let schema = Arc::new(Schema::new(fields));
        let file = File::create(path)?;
        let props = WriterProperties::builder().build();
        let writer = ArrowWriter::try_new(file, schema.clone(), Some(props))?;
        Ok(Self {
            writer,
            schema,
            column_count: columns.len(),
        })
    }

    fn append_rows(&mut self, rows: &[Vec<Option<String>>]) -> Result<(), ParquetExportError> {
        if rows.is_empty() {
            return Ok(());
        }
        // One Arrow column per Parquet column; collect the slice of
        // values for each column index across the batch's rows.
        let mut columns: Vec<ArrayRef> = Vec::with_capacity(self.column_count);
        for col_idx in 0..self.column_count {
            let values: Vec<Option<&str>> = rows
                .iter()
                .map(|row| row.get(col_idx).and_then(|v| v.as_deref()))
                .collect();
            columns.push(Arc::new(StringArray::from(values)));
        }
        let batch = RecordBatch::try_new(self.schema.clone(), columns)?;
        self.writer.write(&batch)?;
        Ok(())
    }

    fn close(self) -> Result<(), ParquetExportError> {
        self.writer.close()?;
        Ok(())
    }
}

/// Registry of in-flight Parquet writers, keyed by an opaque u64
/// handle. The FFI returns the handle to Swift on `open`; Swift
/// passes it back on every `append` and `close`.
pub struct ParquetRegistry {
    next_id: Mutex<u64>,
    exporters: Mutex<HashMap<u64, ParquetExporter>>,
}

impl ParquetRegistry {
    pub fn global() -> &'static Self {
        static REGISTRY: OnceLock<ParquetRegistry> = OnceLock::new();
        REGISTRY.get_or_init(|| ParquetRegistry {
            next_id: Mutex::new(1),
            exporters: Mutex::new(HashMap::new()),
        })
    }

    pub fn open(&self, path: &Path, columns: &[String]) -> Result<u64, ParquetExportError> {
        let exporter = ParquetExporter::create(path, columns)?;
        let id = {
            let mut next = self.next_id.lock().expect("registry poisoned");
            let id = *next;
            *next += 1;
            id
        };
        self.exporters
            .lock()
            .expect("registry poisoned")
            .insert(id, exporter);
        Ok(id)
    }

    pub fn append(&self, id: u64, rows: &[Vec<Option<String>>]) -> Result<(), ParquetExportError> {
        let mut map = self.exporters.lock().expect("registry poisoned");
        let exporter = map.get_mut(&id).ok_or(ParquetExportError::UnknownWriter)?;
        exporter.append_rows(rows)
    }

    pub fn close(&self, id: u64) -> Result<(), ParquetExportError> {
        let exporter = self
            .exporters
            .lock()
            .expect("registry poisoned")
            .remove(&id)
            .ok_or(ParquetExportError::UnknownWriter)?;
        exporter.close()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn write_round_trip() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("test.parquet");
        let registry = ParquetRegistry::global();
        let id = registry
            .open(&path, &["id".into(), "name".into()])
            .expect("open");
        registry
            .append(
                id,
                &[
                    vec![Some("1".into()), Some("alice".into())],
                    vec![Some("2".into()), None],
                ],
            )
            .expect("append");
        registry.close(id).expect("close");
        // File exists with non-zero size — closing flushed the
        // metadata footer.
        let metadata = std::fs::metadata(&path).expect("file exists");
        assert!(metadata.len() > 0);
    }

    #[test]
    fn append_after_close_errors() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("test2.parquet");
        let registry = ParquetRegistry::global();
        let id = registry.open(&path, &["x".into()]).expect("open");
        registry.close(id).expect("close");
        let res = registry.append(id, &[vec![Some("z".into())]]);
        assert!(matches!(res, Err(ParquetExportError::UnknownWriter)));
    }
}
