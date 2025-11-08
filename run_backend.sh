#!/bin/bash

echo "Starting PII Detection Backend Server..."
echo ""
echo "Make sure you have installed dependencies:"
echo "  pip install -r requirements.txt"
echo "  python -m spacy download en_core_web_lg"
echo ""
echo "Starting server on http://127.0.0.1:5000"
echo ""

python app.py

