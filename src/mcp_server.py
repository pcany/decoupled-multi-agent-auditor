import json
import os
from fastapi import FastAPI
from mcp.server.fastmcp import FastMCP

# 1. Wir initialisieren ganz normal FastMCP (ohne Extra-Argumente)
mcp = FastMCP("Security-Audit-Server")

DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")

@mcp.tool()
def read_secure_audit_log(user_id: str) -> str:
    """
    Securely retrieves the conversation history for a specific user ID.
    """
    file_mapping = {
        "usr_9482_alice": "alice_clean.json",
        "usr_3110_bob": "bob_salami_attack.json"
    }
    
    filename = file_mapping.get(user_id)
    if not filename:
        return f"Error: User ID '{user_id}' not found in audit repository."
        
    filepath = os.path.join(DATA_DIR, filename)
    
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
            
        history_text = ""
        for interaction in data.get("conversation_history", []):
            history_text += f"Turn {interaction['turn']} - User: {interaction['user_input']}\n"
        return history_text
    except Exception as e:
        return f"Error reading logs: {str(e)}"

# 2. Wir erstellen eine eigenständige FastAPI App für unsere REST-Route
app = FastAPI(title="Security-Audit-Infrastructure")

@app.post("/api/audit-log")
async def secure_audit_endpoint(request: dict):
    """Expliziter REST-Endpunkt für unseren Agenten-Auditor."""
    arguments = request.get("arguments", {})
    user_id = arguments.get("user_id")
    
    log_content = read_secure_audit_log(user_id)
    return {"content": [{"type": "text", "text": log_content}]}

# 3. Wir mounten die MCP SSE-App auf unsere Haupt-App, falls wir sie später brauchen
# Da mcp.sse_app eine Methode ist, rufen wir sie auf, um die ASGI-App zu erhalten
app.mount("/mcp", mcp.sse_app)

if __name__ == "__main__":
    import uvicorn
    # Wir starten unsere unfehlbare FastAPI App auf Port 8000
    uvicorn.run(app, host="127.0.0.1", port=8000)