import os
from langchain_google_genai import GoogleGenerativeAIEmbeddings, ChatGoogleGenerativeAI
from langchain.chains import RetrievalQA
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain_community.document_loaders import PyPDFLoader, Docx2txtLoader, TextLoader
from langchain_community.vectorstores import Chroma

class RAG_module:
    def __init__(self, document_path, google_api_key):
        self.document_path = document_path
        self.google_api_key = google_api_key
        documents = []
        for file in os.listdir(self.document_path):
            file_path = os.path.join(self.document_path, file)
            if file.endswith(".pdf"):
                loader = PyPDFLoader(file_path)
            elif file.endswith((".docx", ".doc")):
                loader = Docx2txtLoader(file_path)
            elif file.endswith(".txt"):
                loader = TextLoader(file_path)
            else:
                print(f"Unsupported file format: {file}")
                continue
            documents.extend(loader.load())
        text_splitter = RecursiveCharacterTextSplitter(
            chunk_size=1500, chunk_overlap=200, length_function=len
        )
        context = "\n\n".join(str(doc.page_content) for doc in documents)
        texts = text_splitter.split_text(context)
        embeddings = GoogleGenerativeAIEmbeddings(
            model="models/text-embedding-004", google_api_key=self.google_api_key
        )
        vector_index = Chroma.from_texts(texts, embeddings).as_retriever(search_kwargs={"k": 5})

        model = ChatGoogleGenerativeAI(
            model="gemini-1.5-pro", google_api_key=self.google_api_key, temperature=0.2
        )
        self.qa_chain = RetrievalQA.from_chain_type(
            llm=model, retriever=vector_index, return_source_documents=True
        )
    def ask_question(self, query):
        result = self.qa_chain({"query": query})
        return result
