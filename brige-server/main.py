# Bridge Server
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()

queue = []
responses = []


class Prompt(BaseModel):
    text: str


@app.post("/send")
def send_prompt(p: Prompt):
    queue.append(p.text)
    return {"status": "queued"}


@app.get("/get")
def get_prompt():
    if queue:
        return {"prompt": queue.pop(0)}
    return {"prompt": None}


@app.post("/response")
def receive_response(p: Prompt):
    responses.append(p.text)
    return {"status": "received"}


@app.get("/latest")
def latest():
    if responses:
        return {"response": responses.pop(0)}
    return {"response": None}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0", port=8080)
