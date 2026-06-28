import json
import os
import numpy as np
from fastapi import FastAPI
from mcp.server.fastmcp import FastMCP
from google import genai

# 1. Initialisiere die Frameworks
mcp = FastMCP("Security-Audit-Server")
app = FastAPI(title="Security-Audit-Infrastructure")

DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")

def get_embedding(text: str) -> list:
    """Generiert einen mathematischen Vektor mit dem aktuellen gemini-embedding-001 Modell."""
    try:
        client = genai.Client()
        response = client.models.embed_content(
            model="gemini-embedding-001", # Der korrekte, aktive Modellname
            contents=text
        )
        return response.embeddings[0].values
    except Exception as e:
        print(f"[Embedding Error] {e}")
        return []

def calculate_cosine_similarity(vecA, vecB):
    """Berechnet die mathematische Ähnlichkeit (0.0 bis 1.0) zwischen zwei Vektoren."""
    if not vecA or not vecB:
        return 0.0
    dot_product = np.dot(vecA, vecB)
    normA = np.linalg.norm(vecA)
    normB = np.linalg.norm(vecB)
    if normA == 0 or normB == 0:
        return 0.0
    return float(dot_product / (normA * normB))

@mcp.tool()
def read_secure_audit_log(user_id: str, current_input: str = "") -> dict:
    """
    Securely retrieves conversation history and calculates the mathematical 
    semantic drift (similarity) to detect Salami Tactics.
    """
    file_mapping = {
        "usr_9482_alice": "alice_clean.json",
        "usr_3110_bob": "bob_salami_attack.json"
    }
    
    filename = file_mapping.get(user_id)
    if not filename:
        return {"error": f"User ID '{user_id}' not found."}
        
    filepath = os.path.join(DATA_DIR, filename)
    
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
            
        history_turns = data.get("conversation_history", [])
        
        # 1. Extrahiere den reinen Text-Verlauf
        history_text = ""
        last_user_input = ""
        for interaction in history_turns:
            history_text += f"Turn {interaction['turn']} - User: {interaction['user_input']}\n"
            # Wir merken uns den letzten echten Input für den Drift-Vergleich
            if interaction['user_input'] != current_input:
                last_user_input = interaction['user_input']
        
        # 2. Mathematische Drift-Analyse (Cosine Similarity)
        similarity_score = 1.0 
        if current_input and last_user_input:
            vec_current = get_embedding(current_input)
            vec_last = get_embedding(last_user_input)
            similarity_score = calculate_cosine_similarity(vec_current, vec_last)
            
        return {
            "history_text": history_text,
            "metrics": {
                "cosine_similarity_to_last_turn": round(similarity_score, 4),
                "semantic_drift_detected": bool(similarity_score < 0.65)
            }
        }
    except Exception as e:
        return {"error": f"Error reading logs: {str(e)}"}

# 3. Unser sauberer FastAPI-Endpunkt für die main.py Simulation
@app.post("/api/audit-log")
async def secure_audit_endpoint(request: dict):
    """Expliziter REST-Endpunkt, der Text und Metriken liefert."""
    arguments = request.get("arguments", {})
    user_id = arguments.get("user_id")
    current_input = arguments.get("current_input", "")
    
    # Rufe das MCP Tool auf
    analysis_result = read_secure_audit_log(user_id, current_input)
    
    return {"content": [{"type": "text", "text": json.dumps(analysis_result)}]}

app.mount("/mcp", mcp.sse_app)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)