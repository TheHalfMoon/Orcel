# LangChain text copied into the Orcel Agent

`orcel_agent/todos.py` copies, verbatim, three pieces of
`langchain/agents/middleware/todo.py` from the `langchain` 1.3.14 wheel
admitted in `requirements.lock`:

- the `Todo` TypedDict;
- `WRITE_TODOS_TOOL_DESCRIPTION`;
- `WRITE_TODOS_SYSTEM_PROMPT`.

Copying avoids importing that module. Importing it loads LangChain's agent
factory, LangGraph's runtime and `websockets`.

- **Source file SHA-256** (from the wheel):
  `dca1e724b2ef40a5a045bd4cf2902e128e1006c5e77e130a664d77f44d4e1abe`
- **License:** MIT, Copyright (c) LangChain, Inc. See `LICENSE` here, copied
  from the wheel's `licenses/LICENSE`.
