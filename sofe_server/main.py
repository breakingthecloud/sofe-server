import uvicorn

def run():
    uvicorn.run("sofe_server.app:app", host="0.0.0.0", port=8080, reload=False)

if __name__ == "__main__":
    run()