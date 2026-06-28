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
    """Generates a mathematical vector using gemini-embedding-001."""
    try:
        client = genai.Client()
        response = client.models.embed_content(
            model="gemini-embedding-001",
            contents=text
        )
        return response.embeddings[0].values
    except Exception as e:
        print(f"[Embedding Error] {e}")
        return []

def calculate_cosine_similarity(vecA, vecB):
    """Calculates the cosine similarity (0.0 to 1.0) between two vectors."""
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
    Securely retrieves history and calculates both pointwise semantic distance 
    and cumulative centroid drift (Einkreisungs-Entropie).
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
        
        history_text = ""
        last_user_input = ""
        all_past_vectors = []
        
        # 1. Analysiere die Historie und sammle Vektoren für den Schwerpunkt
        for interaction in history_turns:
            u_input = interaction['user_input']
            history_text += f"Turn {interaction['turn']} - User: {u_input}\n"
            
            # Wir berechnen den Schwerpunkt nur aus den *vergangenen* echten Turns
            if u_input != current_input:
                last_user_input = u_input
                vec = get_embedding(u_input)
                if vec:
                    all_past_vectors.append(vec)
        
        # 2. Berechne Metrik 1: Pointwise Cosine Similarity zum letzten Turn
        similarity_to_last = 1.0
        if current_input and last_user_input:
            vec_current = get_embedding(current_input)
            vec_last = get_embedding(last_user_input)
            similarity_to_last = calculate_cosine_similarity(vec_current, vec_last)
        else:
            vec_current = get_embedding(current_input) if current_input else []
            
        # 3. Berechne Metrik 2: Einkreisungs-Entropie (Drift zum globalen Schwerpunkt)
        similarity_to_centroid = 1.0
        if vec_current and all_past_vectors:
            # Mathematischer Mittelpunkt (Zentroid) aller bisherigen Vektoren
            centroid_vector = np.mean(all_past_vectors, axis=0).tolist()
            similarity_to_centroid = calculate_cosine_similarity(vec_current, centroid_vector)
            
        return {
            "history_text": history_text,
            "metrics": {
                "cosine_similarity_to_last_turn": round(similarity_to_last, 4),
                "cosine_similarity_to_centroid": round(similarity_to_centroid, 4),
                "pointwise_drift_detected": bool(similarity_to_last < 0.65),
                "centroid_drift_detected": bool(similarity_to_centroid < 0.70) # Strengerer Schwellenwert für globalen Abdriften
            }
        }
    except Exception as e:
        return {"error": f"Error reading logs: {str(e)}"}

@app.post("/api/audit-log")
async def secure_audit_endpoint(request: dict):
    arguments = request.get("arguments", {})
    user_id = arguments.get("user_id")
    current_input = arguments.get("current_input", "")
    
    analysis_result = read_secure_audit_log(user_id, current_input)
    return {"content": [{"type": "text", "text": json.dumps(analysis_result)}]}

app.mount("/mcp", mcp.sse_app)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)