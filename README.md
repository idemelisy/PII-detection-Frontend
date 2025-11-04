# PII Detection Chrome Extension

A Chrome extension that detects and highlights Personally Identifiable Information (PII) on web pages, with click-to-redact functionality.

## Features

- **Universal PII Detection**: Works on Google Docs, ChatGPT, Gmail, and other web pages
- **Real-time Highlighting**: Highlights detected PII with yellow backgrounds
- **Click-to-Redact**: Click highlighted text to mask it with asterisks
- **Overlay System**: Fallback highlighting for protected content areas
- **Multiple Detection Types**: 
  - Names (PERSON)
  - Locations (LOCATION) 
  - Phone numbers (PHONE)
  - Email addresses (EMAIL)

## Installation

1. Download or clone this repository
2. Open Chrome and go to `chrome://extensions/`
3. Enable "Developer mode" in the top right
4. Click "Load unpacked" and select the extension folder
5. The extension will appear in your extensions list

## Usage

1. Navigate to any supported webpage (Google Docs, ChatGPT, etc.)
2. Look for the green "🛡️ Scan for PII" button in the top-right corner
3. Click the button to scan for PII
4. Yellow highlights will appear over detected PII
5. Click any highlighted text to redact it
6. Use "❌ Clear Highlights" to remove all highlights

## Supported Websites

- ✅ Google Docs
- ✅ ChatGPT (chat.openai.com, chatgpt.com)
- ✅ Gmail
- ✅ Most standard websites

## Files

- `manifest.json` - Extension configuration
- `content.js` - Main detection and highlighting logic
- `style.css` - Styling for buttons and highlights
- `README.md` - This documentation

## Technical Details

The extension uses two highlighting methods:

1. **Direct HTML Modification**: For most websites, directly modifies the DOM
2. **Overlay System**: For protected content (like ChatGPT), creates floating highlights

## Mock Data

Currently uses mock PII data for testing. The extension detects:

- Turkish names: İde, Neris Yılmaz, Dr. Emre Gürsoy, Dr. Saygın
- Locations: Tuzla, İstanbul, Türkiye, Sabancı Üniversitesi
- Phone: 545 333 66 78
- Emails: yücel.saygin@sabanciuniv.edu, emregursoy@gmail.com

## Development

This extension is built for demonstration and educational purposes. In a production environment, the mock data would be replaced with a real PII detection API.

## License

MIT License