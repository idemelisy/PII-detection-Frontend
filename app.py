"""
Flask backend server for PII Detection Chrome Extension
Uses Presidio Analyzer to detect PII in text
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
from presidio_analyzer import AnalyzerEngine
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
# Enable CORS for Chrome extension - allow all origins
# Note: Access-Control-Allow-Private-Network is added in after_request for Chrome Private Network Access
CORS(app, resources={
    r"/*": {
        "origins": "*",
        "methods": ["GET", "POST", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"]
    }
})

# Initialize Presidio Analyzer
logger.info("Initializing Presidio Analyzer...")
try:
    analyzer = AnalyzerEngine()
    logger.info("✅ Presidio Analyzer initialized successfully")
except Exception as e:
    logger.error(f"❌ Error initializing Presidio Analyzer: {e}")
    analyzer = None


def normalize_entity(entity_type: str) -> str:
    """
    Normalize Presidio entity types to match extension's expected format.
    Maps Presidio entity types to the extension's entity types.
    """
    entity_mapping = {
        'PERSON': 'PERSON',
        'EMAIL_ADDRESS': 'EMAIL',
        'PHONE_NUMBER': 'PHONE',
        'LOCATION': 'LOCATION',
        'ORGANIZATION': 'ORGANIZATION',
        'CREDIT_CARD': 'CREDIT_CARD',
        'SSN': 'SSN',
        'IP_ADDRESS': 'IP_ADDRESS',
        'DATE_TIME': 'DATE_TIME',
        'URL': 'URL',
        'US_DRIVER_LICENSE': 'ID',
        'US_PASSPORT': 'ID',
        'US_BANK_NUMBER': 'BANK_ACCOUNT',
        'IBAN_CODE': 'BANK_ACCOUNT',
        'US_SSN': 'SSN',
        'MEDICAL_LICENSE': 'ID',
        'NPI': 'ID',
    }
    return entity_mapping.get(entity_type, entity_type)


def presidio_detect_pii(text: str, language: str = "en") -> list:
    """
    Analyze text with Presidio and return detected entities in extension format.
    
    Args:
        text: Input text to analyze
        language: Language code (default: "en")
    
    Returns:
        List of detected PII entities in format:
        [
            {
                "type": "PERSON",
                "start": 5,
                "end": 8,
                "value": "John",
                "confidence": 0.95
            },
            ...
        ]
    """
    if not analyzer:
        logger.error("Presidio Analyzer not initialized")
        return []
    
    if not isinstance(text, str) or not text.strip():
        return []
    
    try:
        # Analyze text for PII
        results = analyzer.analyze(text=text, language=language)
        
        # Convert Presidio results to extension format
        entities = []
        for r in results:
            entity_type = normalize_entity(r.entity_type)
            entity_value = text[r.start:r.end]
            
            entities.append({
                "type": entity_type,
                "start": r.start,
                "end": r.end,
                "value": entity_value,
                "confidence": r.score
            })
        
        logger.info(f"Detected {len(entities)} PII entities in text")
        return entities
        
    except Exception as e:
        logger.error(f"Error processing text: {e}", exc_info=True)
        return []


@app.after_request
def after_request(response):
    """Add CORS headers to all responses"""
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,POST,OPTIONS')
    # Required for Chrome Private Network Access (CORS-RFC1918)
    # Allows HTTPS pages to access localhost
    response.headers.add('Access-Control-Allow-Private-Network', 'true')
    return response

@app.route('/health', methods=['GET', 'OPTIONS'])
def health_check():
    """Health check endpoint"""
    if request.method == 'OPTIONS':
        # Handle preflight request with all necessary headers
        response = app.make_default_options_response()
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Methods', 'GET, OPTIONS')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type')
        response.headers.add('Access-Control-Allow-Private-Network', 'true')
        return response
    
    logger.info(f"Health check request from {request.remote_addr}")
    return jsonify({
        "status": "healthy",
        "presidio_initialized": analyzer is not None
    }), 200


@app.route('/detect-pii', methods=['POST', 'OPTIONS'])
def detect_pii():
    """
    Main endpoint for PII detection.
    
    Expected request body:
    {
        "text": "Text to analyze for PII",
        "language": "en" (optional, default: "en"),
        "model": "presidio" (optional, for future use)
    }
    
    Returns:
    {
        "has_pii": true/false,
        "detected_entities": [...],
        "total_entities": 5,
        "model_used": "presidio",
        "confidence_threshold": 0.8
    }
    """
    # Handle preflight OPTIONS request
    if request.method == 'OPTIONS':
        # Handle preflight request with all necessary headers
        response = app.make_default_options_response()
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Methods', 'POST, OPTIONS')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        response.headers.add('Access-Control-Allow-Private-Network', 'true')
        return response
    try:
        # Log incoming request
        logger.info(f"PII detection request from {request.remote_addr}")
        logger.info(f"Request headers: {dict(request.headers)}")
        
        # Get request data
        data = request.get_json()
        
        if not data:
            logger.warning("No JSON data provided in request")
            return jsonify({"error": "No JSON data provided"}), 400
        
        text = data.get('text', '')
        language = data.get('language', 'en')
        model = data.get('model', 'presidio')
        
        logger.info(f"Processing request: text length={len(text)}, language={language}, model={model}")
        
        if not text or not text.strip():
            logger.info("Empty text provided, returning empty result")
            return jsonify({
                "has_pii": False,
                "detected_entities": [],
                "total_entities": 0,
                "model_used": model,
                "confidence_threshold": 0.8
            }), 200
        
        # Detect PII using Presidio
        detected_entities = presidio_detect_pii(text, language)
        
        # Filter by confidence threshold (optional, can be made configurable)
        confidence_threshold = 0.6
        filtered_entities = [
            e for e in detected_entities 
            if e.get('confidence', 0) >= confidence_threshold
        ]
        
        # Format response to match extension's expected format
        response = {
            "has_pii": len(filtered_entities) > 0,
            "detected_entities": filtered_entities,
            "total_entities": len(filtered_entities),
            "model_used": model,
            "confidence_threshold": confidence_threshold
        }
        
        logger.info(f"Processed request: {len(filtered_entities)} entities detected")
        return jsonify(response), 200
        
    except Exception as e:
        logger.error(f"Error in detect-pii endpoint: {e}", exc_info=True)
        return jsonify({
            "error": "Internal server error",
            "message": str(e)
        }), 500


@app.route('/', methods=['GET'])
def index():
    """Root endpoint with API information"""
    return jsonify({
        "service": "PII Detection API",
        "version": "1.0",
        "endpoints": {
            "health": "/health",
            "detect_pii": "/detect-pii (POST)"
        },
        "status": "running"
    }), 200


if __name__ == '__main__':
    # Run the Flask app
    # Default to localhost:5000, but can be configured via environment variables
    import os
    host = os.getenv('HOST', '127.0.0.1')
    port = int(os.getenv('PORT', 5000))
    
    logger.info(f"Starting PII Detection API server on {host}:{port}")
    app.run(host=host, port=port, debug=True)

