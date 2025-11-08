import json
from datasets import load_dataset
from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig
import spacy

print("🚀 Starting fresh Presidio PII detection...")

# ---- 1. Initialize Presidio with en_core_web_lg ----
print("📝 Initializing Presidio...")
analyzer = AnalyzerEngine()
anonymizer = AnonymizerEngine()





def presidio_detect_pii(text: str):
    """Analyze text with Presidio and return detected entities."""
    if not isinstance(text, str) or not text.strip():
        return []
    
    try:
        # Analyze text for PII
        results = analyzer.analyze(text=text, language="en")
        return [
            {
                "label": normalize_entity(r.entity_type),
                "text": text[r.start:r.end],
                "start": r.start,
                "end": r.end,
                "confidence": r.score
            }
            for r in results
        ]
    except Exception as e:
        print(f"Error processing text: {e}")
        return []



# ---- 3. Apply Presidio to each document ----
print("🔍 Running Presidio detection...")
processed_docs = []

for i, doc in enumerate(data):
    if i % 100 == 0:
        print(f"Processing document {i+1}/{len(data)}")
    
    doc_id = doc.get("doc_id", f"doc_{i}")
    text = doc.get("text", "")
    annotations = doc.get("annotations", [])
    
    # Run Presidio detection
    detected_pii = presidio_detect_pii(text)
    
    # Create clean document structure
    processed_doc = {
        "doc_id": doc_id,
        "text": text,
        "annotations": annotations,
        "presidio_detected_pii": detected_pii
    }
    
    processed_docs.append(processed_doc)



print("🏁 Presidio detection complete!")