import subprocess
from pathlib import Path

import lancedb
import polars as pl
from lancedb.table import Table
from pydantic import BaseModel, ConfigDict

from tracecat.config import TRACECAT__CSPM_DIR, TRACECAT__VECTORDB_DIR
from tracecat.embeddings import embed_batch, with_embeddings


def _get_workdir() -> Path:
    path = Path(TRACECAT__CSPM_DIR)
    path.mkdir(parents=True, exist_ok=True)
    return path


def _get_latest_report() -> Path:
    """Return the newest prowler report."""
    return max(_get_workdir().glob("*.json"), key=lambda x: x.stat().st_ctime)


def _get_latest_report_embs() -> Path:
    """Return the newest prowler report."""
    return max(_get_workdir().glob("*.parquet"), key=lambda x: x.stat().st_ctime)


def _get_lancedb() -> lancedb.db.DBConnection:
    return lancedb.connect(TRACECAT__VECTORDB_DIR)


def get_latest_report_df() -> pl.DataFrame:
    """Return the latest prowler report as a DataFrame."""
    return pl.read_json(_get_latest_report())


def run_prowler():
    """TODO: Run prowler and return the results as a JSON object."""
    # prowler <provider> -M csv json json-asff html -F <custom_report_name> -o <custom_report_directory>
    base_path = _get_workdir()
    subprocess.run(
        [
            "prowler",
            "aws",
            "-M",
            "json",
            "-o",
            str(base_path),
        ],
    )


def create_embeddings_for_prowler_report(
    *, report_path: Path, output_path: Path
) -> pl.DataFrame:
    """Create embeddings (smallest unique set) for the prowler report."""
    emb_text_col = "embed_text"
    df = (
        pl.read_json(report_path)
        .lazy()
        .with_columns(
            pl.format(
                "Description: {}; Risk: {}", pl.col.Description, pl.col.Risk
            ).alias(emb_text_col)
        )
        .group_by(emb_text_col)
        .agg(pl.col.FindingUniqueId)
        .collect(streaming=True)
        .pipe(with_embeddings, emb_text_col)
    )
    df.write_parquet(output_path)
    return df


def create_lancedb_table_from_embeddings(
    path: Path, *, table_name: str | None = None
) -> Table:
    """Ingest the raw prowler report into the lancedb."""

    table_name = table_name or "cspm_prowler"
    df = pl.read_parquet(path)
    # TODO(lance): Switch this out for hybrid search
    table = _get_lancedb().create_table(table_name, data=df, exist_ok=True)
    return table


class SearchResult(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    table_name: str
    query: str
    data: pl.DataFrame


def search(query: str, table_name: str | None = None, limit: int = 10) -> SearchResult:
    """Search lancedb for a query."""
    tbl = _get_lancedb().open_table(table_name or "cspm_prowler")
    embeddings = embed_batch([query])
    emb = embeddings[0].embedding
    results = tbl.search(emb).metric("cosine").limit(limit).to_polars()
    return SearchResult(
        table_name=table_name,
        query=query,
        data=results,
    )


def search_many(
    queries: list[str], table_name: str | None = None, limit: int = 10
) -> list[SearchResult]:
    """Search lanccedb over many queries."""
    tbl = _get_lancedb().open_table(table_name or "cspm_prowler")
    embeddings = embed_batch(queries)
    results = []
    for query, emb in zip(queries, embeddings, strict=True):
        search_res = tbl.search(emb.embedding).metric("cosine").limit(limit).to_polars()
        results.append(
            SearchResult(table_name=table_name, query=query, data=search_res)
        )
    return results
