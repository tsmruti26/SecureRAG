from pathlib import Path

from langchain_chroma import Chroma
from langchain_core.documents import Document
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_text_splitters import RecursiveCharacterTextSplitter

BASE_DIR = Path(__file__).resolve().parent
KB_DIR = BASE_DIR / "SecureRAG_SOC_Knowledge_Base"

if not KB_DIR.exists():
    raise FileNotFoundError(f"SOC knowledge base not found: {KB_DIR}")

embeddings = HuggingFaceEmbeddings(
    model_name="sentence-transformers/all-MiniLM-L6-v2",
    model_kwargs={"device": "cpu"},
)
vector_store = Chroma(
    collection_name="soc_security_kb",
    embedding_function=embeddings,
    persist_directory=str(BASE_DIR / "chroma_db"),
)

# Split on markdown headings first so each chunk stays on one topic.
splitter = RecursiveCharacterTextSplitter(
    chunk_size=1200,
    chunk_overlap=150,
    separators=["\n## ", "\n### ", "\n\n", "\n", " ", ""],
)

chunks, ids = [], []
files = 0
for path in sorted(KB_DIR.glob("*.md")):
    if path.name.lower() == "readme.md":
        continue
    content = path.read_text(encoding="utf-8").strip()
    if not content:
        continue
    files += 1
    title = content.splitlines()[0].lstrip("# ").strip()
    for i, part in enumerate(splitter.split_text(content)):
        chunks.append(
            Document(
                page_content=f"[{title}]\n{part}",
                metadata={
                    "source": path.name,
                    "title": title,
                    "chunk": i,
                    "department": "soc",
                    "classification": "internal",
                },
            )
        )
        ids.append(f"{path.name}:{i}")
    vector_store.delete(where={"source": path.name})  # replace earlier copies

if not chunks:
    raise RuntimeError(f"No SOC Markdown playbooks found in {KB_DIR}")

vector_store.add_documents(chunks, ids=ids)
print(f"Indexed {files} playbooks as {len(chunks)} chunks.")
print(f"Collection: {vector_store._collection.name} ({vector_store._collection.count()} total)")
