from typing import Literal

import numpy as np
import openai
import polars as pl
from openai.types import Embedding

OPENAI_EMBEDDING_SIZE = 1536

client = openai.OpenAI()
async_client = openai.AsyncOpenAI()

ModelTypes = Literal["text-embedding-3-small", "text-embedding-3-large"]


def embed_batch(
    texts: list[str], model: ModelTypes = "text-embedding-3-small"
) -> list[Embedding]:
    texts = [text.replace("\n", " ") for text in texts]
    response = client.embeddings.create(input=texts, model=model)
    return response.data


async def async_embed_batch(texts: list[str], model: ModelTypes) -> list[Embedding]:
    texts = [text.replace("\n", " ") for text in texts]
    response = await async_client.embeddings.create(input=texts, model=model)
    return response.data


def with_embeddings(
    df: pl.DataFrame, /, text_col: str, model: ModelTypes = "text-embedding-3-small"
) -> pl.DataFrame:
    """Return a polars DataFrame with an additional column of OpenAI embeddings."""
    embeddings = embed_batch(df[text_col], model=model)
    embs_arr = np.array([e.embedding for e in embeddings])
    return df.with_columns(vector=embs_arr)
