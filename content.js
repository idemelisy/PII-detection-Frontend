// --- PII Detector with Backend API ---
// This script connects to the Presidio backend for real PII detection.
console.log("PII Detector Content Script Loaded! (Backend API Mode)");

// Global error handler to prevent crashes
window.addEventListener("error", (e) => {
    console.error("[PII Extension] Global error caught:", e.message, e.error);
    console.error("[PII Extension] Error stack:", e.error?.stack);
});

// Global unhandled promise rejection handler
window.addEventListener("unhandledrejection", (e) => {
    console.error("[PII Extension] Unhandled promise rejection:", e.reason);
    e.preventDefault(); // Prevent the default browser behavior
});

// Highlighting class (must synchronize with style.css)
const HIGHLIGHT_CLASS = 'pii-highlight'; 
const REDACT_BTN_CLASS = 'pii-redact-btn';
const SUGGESTION_POPUP_CLASS = 'pii-suggestion-popup';
const REJECTED_CLASS = 'pii-rejected';

// Track suggestion states
const suggestionStates = new Map(); // Store accept/reject decisions

// Current selected model for PII detection
let currentModel = 'presidio'; // Default model (now using real Presidio backend)

// Backend API configuration
const BACKEND_API_URL = 'http://127.0.0.1:5000/detect-pii'; // Change this to your backend URL
const BACKEND_HEALTH_URL = 'http://127.0.0.1:5000/health';

// Model configurations with different mock data sets
const MODEL_CONFIGS = {
    piranha: {
        name: " Piranha",
        description: "Fast and aggressive PII detection",
        accuracy: "High"
    },
    presidio: {
        name: " Presidio", 
        description: "Microsoft's PII detection engine",
        accuracy: "Very High"
    },
    ai4privacy: {
        name: " AI4Privacy",
        description: "Privacy-focused detection model",
        accuracy: "High"
    },
    bdmbz: {
        name: " BDMBZ",
        description: "Lightning-fast detection",
        accuracy: "Medium"
    },
    nemo: {
        name: " NEMO",
        description: "Precision-targeted detection",
        accuracy: "Very High"
    }
};

// Check if backend is available using background script (avoids CORS issues)
async function checkBackendHealth() {
    try {
        console.log("[PII Extension] Checking backend health via background script...");
        
        return new Promise((resolve) => {
            const timeout = setTimeout(() => {
                console.warn("[PII Extension] Health check timed out");
                resolve(false);
            }, 5000);
            
            chrome.runtime.sendMessage(
                { action: 'checkHealth' },
                (response) => {
                    clearTimeout(timeout);
                    if (chrome.runtime.lastError) {
                        console.warn("[PII Extension] Background script error:", chrome.runtime.lastError.message);
                        resolve(false);
                        return;
                    }
                    
                    if (response && response.success) {
                        const data = response.data;
                        console.log("[PII Extension] Health check response:", data);
                        const isHealthy = data.status === 'healthy' && data.presidio_initialized === true;
                        console.log("[PII Extension] Backend is healthy:", isHealthy);
                        resolve(isHealthy);
                    } else {
                        console.warn("[PII Extension] Health check failed:", response?.error);
                        resolve(false);
                    }
                }
            );
        });
    } catch (error) {
        console.warn("[PII Extension] Backend health check failed:", error.message || error);
        return false;
    }
}

// Call backend API to detect PII using background script (avoids CORS issues)
async function detectPIIFromBackend(text, model = 'presidio') {
    try {
        console.log(`[PII Extension] Calling backend API for PII detection via background script (model: ${model})...`);
        
        return new Promise((resolve, reject) => {
            const timeout = setTimeout(() => {
                reject(new Error("Request timed out. The text might be too long or the server is slow."));
            }, 30000);
            
            chrome.runtime.sendMessage(
                {
                    action: 'detectPII',
                    text: text,
                    language: 'en',
                    model: model
                },
                (response) => {
                    clearTimeout(timeout);
                    
                    if (chrome.runtime.lastError) {
                        console.error("[PII Extension] Background script error:", chrome.runtime.lastError.message);
                        reject(new Error("Cannot connect to backend server. Please ensure the server is running."));
                        return;
                    }
                    
                    if (response && response.success) {
                        const data = response.data;
                        console.log(`[PII Extension] Backend detected ${data.total_entities} PII entities`);
                        resolve(data);
                    } else {
                        const errorMsg = response?.error || "Unknown error";
                        console.error("[PII Extension] Backend API error:", errorMsg);
                        reject(new Error(errorMsg));
                    }
                }
            );
        });
    } catch (error) {
        console.error("[PII Extension] Error calling backend API:", error.message || error);
        throw error;
    }
}

// Fallback to mock data if backend is unavailable (for development/testing)
function getMockPIIData(model = 'presidio') {
    console.warn("[PII Extension] Using fallback mock data - backend unavailable");
    const baseEntities = [
        { "type": "PERSON", "start": 5, "end": 8, "value": "İde" },
        { "type": "PERSON", "start": 42, "end": 54, "value": "Neris Yılmaz" },
        { "type": "EMAIL", "start": 286, "end": 313, "value": "yücel.saygin@sabanciuniv.edu" },
        { "type": "EMAIL", "start": 316, "end": 337, "value": "emregursoy@gmail.com" },
        { "type": "PHONE", "start": 180, "end": 193, "value": "545 333 66 78" }
    ];

    return {
        "has_pii": baseEntities.length > 0,
        "detected_entities": baseEntities,
        "total_entities": baseEntities.length,
        "model_used": model,
        "confidence_threshold": 0.8
    };
}

// Inject the Scan button into the Google Docs interface
function injectScanButton() {
  // Check if container already exists to avoid duplicates
  if (!document.getElementById("pii-scan-container")) {
    
    const container = document.createElement("div");
    container.id = "pii-scan-container";
    
    // Scan button (Turuncu logolu)
    const scanButton = document.createElement("button");
    scanButton.id = "pii-scan-button";
    scanButton.innerHTML = `<span role="img" aria-label="Shield">🛡️</span> Scan for PII`;
    scanButton.onclick = handleScanClick;

    // Clear button
    const clearButton = document.createElement("button");
    clearButton.id = "pii-clear-button";
    clearButton.innerHTML = `<span role="img" aria-label="Clear">❌</span> Clear Highlights`;
    clearButton.onclick = clearHighlights;
    
    // Accept All button
    const acceptAllButton = document.createElement("button");
    acceptAllButton.id = "pii-accept-all-button";
    acceptAllButton.innerHTML = `<span role="img" aria-label="Accept All">✅</span> Accept All`;
    acceptAllButton.onclick = acceptAllPII;
    
    // Model Selection Dropdown
    const modelSelectContainer = document.createElement("div");
    modelSelectContainer.id = "pii-model-container";
    
    const modelLabel = document.createElement("label");
    modelLabel.htmlFor = "pii-model-select";
    modelLabel.textContent = "Model:";
    modelLabel.style.fontSize = "12px";
    modelLabel.style.color = "#048BA8";
    modelLabel.style.fontWeight = "600";
    modelLabel.style.marginBottom = "4px";
    modelLabel.style.display = "block";
    
    const modelSelect = document.createElement("select");
    modelSelect.id = "pii-model-select";
    modelSelect.innerHTML = `
        <option value="piranha" selected>🐟 Piranha (Current)</option>
        <option value="presidio">🛡️ Presidio</option>
        <option value="ai4privacy">🔒 AI4Privacy</option>
        <option value="bdmbz">⚡ BDMBZ</option>
        <option value="nemo">🎯 NEMO</option>
    `;
    modelSelect.onchange = handleModelChange;
    
    modelSelectContainer.appendChild(modelLabel);
    modelSelectContainer.appendChild(modelSelect);
    
    container.appendChild(scanButton);
    container.appendChild(clearButton);
    container.appendChild(acceptAllButton);
    container.appendChild(modelSelectContainer);
    
    // Append the container directly to the body (CSS handles positioning to top-right)
    document.body.appendChild(container);
    console.log("PII Scan buttons injected successfully to document.body");
  } else {
    console.log("PII Scan container already exists, skipping injection");
  }
}

// Universal content finder that works on different page types
function findContentArea() {
  const pageType = detectPageType();
  console.log(`Finding content area for page type: ${pageType}`);
  
  // IMPORTANT: For ChatGPT and Gemini, ONLY scan the input textarea
  // Never scan the conversation history
  if (pageType === 'chatgpt' || pageType === 'gemini') {
    console.log(`[PII Extension] ${pageType === 'gemini' ? 'Gemini' : 'ChatGPT'} detected - using textarea-only approach`);
    
    // Try multiple selectors for textarea/input fields
    const textareaSelectors = [
      'textarea[aria-label*="prompt"]',
      'textarea[aria-label*="message"]',
      'textarea[placeholder*="prompt"]',
      'textarea[placeholder*="message"]',
      'textarea[contenteditable="true"]',
      'div[contenteditable="true"][role="textbox"]',
      'textarea'
    ];
    
    let textarea = null;
    for (const selector of textareaSelectors) {
      textarea = document.querySelector(selector);
      if (textarea) {
        console.log(`[PII Extension] Found input field with selector: ${selector}`);
        break;
      }
    }
    
    if (textarea) {
      // Create a virtual container with ONLY the textarea content for scanning
      const virtualContainer = document.createElement('div');
      virtualContainer.textContent = textarea.value || textarea.textContent || '';
      console.log(`[PII Extension] Scanning only input field content (${virtualContainer.textContent.length} characters)`);
      return virtualContainer;
    } else {
      console.warn("[PII Extension] No textarea/input field found");
      return null;
    }
  }
  
  let contentSelectors = [];
  
  switch(pageType) {
    case 'google-docs':
      contentSelectors = [
        '.kix-page-content-wrap .kix-page',
        '.kix-page-content-wrap',
        '.kix-canvas-tile-content',
        '.kix-paginateddocument'
      ];
      break;
      
    case 'gmail':
       contentSelectors = [
        '.ii.gt .a3s.aiL', // Email message content (main)
        '.ii.gt .a3s', // Alternative message content
        '[role="listitem"] .a3s', // Message in conversation view
        '.adn.ads .a3s', // Message body alternative
        '.ii.gt', // Message container
        '.gs .a3s', // Another message format
        '.h7', // Email body alternative
        '.Am.Al.editable', // Compose window
        '[g_editable="true"]', // Gmail compose area
        '.editable', // Generic editable area
        '[contenteditable="true"]', // Any contenteditable area
        '.gmail_default' // Gmail default content
      ];
      break;
      
    default: // general-web
      contentSelectors = [
        'main',
        'article',
        '.content',
        '#content',
        '.post',
        '.entry-content',
        'body'
      ];
  }
  
  // Try each selector for non-ChatGPT pages
  for (const selector of contentSelectors) {
    const element = document.querySelector(selector);
    if (element) {
      console.log(`Testing selector: ${selector}`);
      console.log(`Element textContent length: ${element.textContent.length}`);
      console.log(`Sample content: "${element.textContent.substring(0, 200)}"`);
      
      const textNodes = getSimpleTextNodesIn(element);
      console.log(`Found ${textNodes.length} text nodes`);
      
      if (textNodes.length > 0) {
        // For Google Docs, check for document content
        if (pageType === 'google-docs') {
          const combinedText = textNodes.map(n => n.textContent).join(' ');
          if (combinedText.includes('İde') || combinedText.includes('Tuzla') || combinedText.includes('Neris')) {
            console.log(`Found Google Docs content using selector: ${selector}`);
            return element;
          }
        } else if (pageType === 'gmail') {
          // For Gmail, check if content contains email-like content or our PII
          const combinedText = textNodes.map(n => n.textContent).join(' ');
          console.log(`Gmail content sample: "${combinedText.substring(0, 100)}"`);
          if (combinedText.includes('İde') || combinedText.includes('Tuzla') || combinedText.includes('Neris') || 
              combinedText.includes('emregursoy@gmail.com') || combinedText.includes('yücel.saygin') ||
              combinedText.includes('@') || combinedText.length > 100) { // Email content indicators
            console.log(`Found Gmail email content using selector: ${selector}`);
            return element;
          }
        } else {
          // For other pages, any text content is good
          console.log(`Found content area using selector: ${selector}`);
          return element;
        }
      }
    }
  }
  
  // Fallback: use document.body for non-ChatGPT pages
  if (pageType !== 'chatgpt') {
    console.log("Using document.body as fallback");
    return document.body;
  }
  
  return null;
}

// Generate unique suggestion ID
function generateSuggestionId() {
    return 'suggestion_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
}

// Get redaction label based on PII type
function getRedactionLabel(piiType) {
    const labels = {
        'PERSON': '[NAME]',
        'LOCATION': '[LOCATION]', 
        'EMAIL': '[EMAIL]',
        'PHONE': '[PHONE]',
        'ORGANIZATION': '[ORGANIZATION]'
    };
    return labels[piiType] || '[REDACTED]';
}

// Check if a text position overlaps with already-redacted text
function isRedactedText(text, start, end) {
    // Check if the text at this position contains redaction labels
    const textAtPosition = text.substring(start, end);
    const redactionLabels = ['[NAME]', '[LOCATION]', '[EMAIL]', '[PHONE]', '[ORGANIZATION]', '[REDACTED]'];
    
    // Check if the position is within a redaction label
    for (const label of redactionLabels) {
        const labelIndex = text.indexOf(label);
        if (labelIndex !== -1) {
            const labelEnd = labelIndex + label.length;
            // Check if our PII position overlaps with this redaction label
            if ((start >= labelIndex && start < labelEnd) || 
                (end > labelIndex && end <= labelEnd) ||
                (start <= labelIndex && end >= labelEnd)) {
                return true;
            }
        }
    }
    
    // Also check if the text itself is a redaction label
    return redactionLabels.some(label => textAtPosition.includes(label));
}

// Filter out PII entities that overlap with already-redacted text
function filterRedactedPII(entities, text) {
    return entities.filter(entity => {
        // Check if this entity overlaps with any redaction label
        const redactionLabels = ['[NAME]', '[LOCATION]', '[EMAIL]', '[PHONE]', '[ORGANIZATION]', '[REDACTED]'];
        
        // Find all redaction labels in the text
        const redactionRanges = [];
        for (const label of redactionLabels) {
            let searchIndex = 0;
            while (true) {
                const labelIndex = text.indexOf(label, searchIndex);
                if (labelIndex === -1) break;
                redactionRanges.push({
                    start: labelIndex,
                    end: labelIndex + label.length
                });
                searchIndex = labelIndex + 1;
            }
        }
        
        // Check if entity overlaps with any redaction range
        for (const range of redactionRanges) {
            if ((entity.start >= range.start && entity.start < range.end) || 
                (entity.end > range.start && entity.end <= range.end) ||
                (entity.start <= range.start && entity.end >= range.end)) {
                console.log(`[PII Extension] Filtering out PII "${entity.value}" at ${entity.start}-${entity.end} - overlaps with redaction label`);
                return false;
            }
        }
        
        // Also check if the entity text itself contains a redaction label
        const entityText = text.substring(entity.start, entity.end);
        if (redactionLabels.some(label => entityText.includes(label))) {
            console.log(`[PII Extension] Filtering out PII "${entity.value}" - contains redaction label`);
            return false;
        }
        
        return true;
    });
}

// ChatGPT Integration Helper Functions
// These functions safely update ChatGPT's input using React's synthetic event system

// Safely set ChatGPT/Gemini input value and trigger React state update
function setChatGPTInputValue(newText, textareaElement = null) {
    try {
        // Use provided textarea or try to find it
        let textarea = textareaElement;
        if (!textarea) {
            const textareaSelectors = [
                'textarea[aria-label*="prompt"]',
                'textarea[aria-label*="message"]',
                'textarea[placeholder*="prompt"]',
                'textarea[placeholder*="message"]',
                'textarea[contenteditable="true"]',
                'div[contenteditable="true"][role="textbox"]',
                'textarea'
            ];
            
            for (const selector of textareaSelectors) {
                textarea = document.querySelector(selector);
                if (textarea) break;
            }
        }
        
        if (!textarea) {
            console.warn("[PII Extension] Input field not found");
            return false;
        }
        
        const pageType = detectPageType();
        console.log(`[PII Extension] Setting ${pageType === 'gemini' ? 'Gemini' : 'ChatGPT'} input value safely...`);
        
        // IMPORTANT: Only update the value, never replace DOM nodes
        // Handle both textarea.value and contenteditable divs
        if (textarea.tagName === 'TEXTAREA') {
            textarea.value = newText;
        } else {
            textarea.textContent = newText;
        }
        
        // Dispatch React-compatible events to maintain state sync
        const inputEvent = new Event("input", { bubbles: true });
        textarea.dispatchEvent(inputEvent);
        
        // Also dispatch change event for compatibility
        const changeEvent = new Event("change", { bubbles: true });
        textarea.dispatchEvent(changeEvent);
        
        // Focus to ensure proper React state
        textarea.focus();
        
        console.log(`[PII Extension] ${pageType === 'gemini' ? 'Gemini' : 'ChatGPT'} input updated successfully without DOM manipulation`);
        return true;
    } catch (error) {
        console.error("[PII Extension] Error updating input field:", error);
        return false;
    }
}

// Toggle ChatGPT send button state during processing
function toggleChatGPTSendButton(enabled) {
    try {
        // Try multiple possible selectors for the send button
        const sendButtonSelectors = [
            'button[data-testid="send-button"]',
            'button[aria-label*="Send"]',
            'button[aria-label*="send"]',
            '[data-testid="send-button"]',
            'form button[type="submit"]',
            'button:has(svg):last-of-type'
        ];
        
        let sendBtn = null;
        for (const selector of sendButtonSelectors) {
            try {
                sendBtn = document.querySelector(selector);
                if (sendBtn) {
                    console.log(`[PII Extension] Found send button with selector: ${selector}`);
                    break;
                }
            } catch (selectorError) {
                console.warn(`[PII Extension] Error with selector ${selector}:`, selectorError);
            }
        }
        
        if (sendBtn) {
            // IMPORTANT: Only modify properties, never replace the element
            sendBtn.disabled = !enabled;
            sendBtn.style.opacity = enabled ? '1' : '0.5';
            sendBtn.style.pointerEvents = enabled ? 'auto' : 'none';
            console.log(`[PII Extension] Send button ${enabled ? 'enabled' : 'disabled'} safely`);
            return true;
        } else {
            console.warn("[PII Extension] ChatGPT send button not found");
            return false;
        }
    } catch (error) {
        console.error("[PII Extension] Error toggling send button:", error);
        return false;
    }
}

// Extract sanitized text from the content area after redactions
function extractSanitizedText() {
    try {
        const editor = findContentArea();
        if (!editor) {
            console.warn("[PII Extension] No content area found for text extraction");
            return null;
        }
        
        let sanitizedText = '';
        
        // Walk through all text nodes and redacted elements safely
        const walker = document.createTreeWalker(
            editor,
            NodeFilter.SHOW_TEXT | NodeFilter.SHOW_ELEMENT,
            {
                acceptNode: function(node) {
                    try {
                        // Accept text nodes
                        if (node.nodeType === Node.TEXT_NODE && node.textContent.trim()) {
                            return NodeFilter.FILTER_ACCEPT;
                        }
                        // Accept redacted spans
                        if (node.nodeType === Node.ELEMENT_NODE && 
                            node.classList && node.classList.contains('pii-redacted')) {
                            return NodeFilter.FILTER_ACCEPT;
                        }
                        return NodeFilter.FILTER_SKIP;
                    } catch (error) {
                        console.error("[PII Extension] Error in node filter:", error);
                        return NodeFilter.FILTER_SKIP;
                    }
                }
            }
        );
        
        let node;
        while (node = walker.nextNode()) {
            try {
                if (node.nodeType === Node.TEXT_NODE) {
                    sanitizedText += node.textContent;
                } else if (node.classList && node.classList.contains('pii-redacted')) {
                    sanitizedText += node.textContent; // This will be the redaction label like [NAME]
                }
            } catch (error) {
                console.error("[PII Extension] Error processing node:", error);
            }
        }
        
        return sanitizedText.trim();
    } catch (error) {
        console.error("[PII Extension] Error extracting sanitized text:", error);
        return null;
    }
}

// Simplified text node finder without aggressive filtering
function getSimpleTextNodesIn(element) {
    const textNodes = [];
    const walker = document.createTreeWalker(
        element,
        NodeFilter.SHOW_TEXT,
        {
            acceptNode: function(node) {
                // Only skip completely empty nodes and script/style
                if (node.textContent.trim().length === 0) {
                    return NodeFilter.FILTER_REJECT;
                }
                const parent = node.parentElement;
                if (parent && (parent.tagName === 'SCRIPT' || parent.tagName === 'STYLE')) {
                    return NodeFilter.FILTER_REJECT;
                }
                return NodeFilter.FILTER_ACCEPT;
            }
        }
    );
    
    let node;
    while (node = walker.nextNode()) {
        textNodes.push(node);
    }
    
    return textNodes;
}

// Clears all PII highlights from the document
function clearHighlights(showAlert = true) {
    try {
        const pageType = detectPageType();
        const isChatGPTOrGemini = pageType === 'chatgpt' || pageType === 'gemini';
        
        // For ChatGPT/Gemini, clear textarea overlays
        if (isChatGPTOrGemini) {
            // Remove all textarea overlay highlights
            document.querySelectorAll('.pii-textarea-overlay').forEach(el => {
                if (el._updatePosition) {
                    window.removeEventListener('scroll', el._updatePosition, true);
                    window.removeEventListener('resize', el._updatePosition);
                }
                el.remove();
            });
            
            // Remove any suggestion popups
            document.querySelectorAll('.pii-suggestion-popup').forEach(popup => {
                popup.remove();
            });
            
            // Clear stored data
            delete window.chatGPTOriginalText;
            delete window.chatGPTFoundPII;
            delete window.chatGPTTextarea;
            
            if (showAlert) {
                alert("Highlights cleared.");
            }
            
            console.log("[PII Extension] Cleared ChatGPT/Gemini highlights");
            return;
        }
        
        // Clear regular highlights by replacing HTML
        const editor = findContentArea();
        let highlightedElements = [];
        let redactedElements = [];
        let textHighlightCount = 0;
        
        if (editor) {
            try {
                // Find highlighted spans
                highlightedElements = editor.querySelectorAll(`.${HIGHLIGHT_CLASS}`);
                textHighlightCount = highlightedElements.length;
                
                // Find redacted spans
                redactedElements = editor.querySelectorAll('.pii-redacted');
                
                // Replace highlights with original text safely
                if (textHighlightCount > 0) {
                    highlightedElements.forEach((el, index) => {
                        try {
                            if (el.parentNode && el.parentNode.nodeType === Node.ELEMENT_NODE) {
                                const textNode = document.createTextNode(el.textContent);
                                el.parentNode.replaceChild(textNode, el);
                            }
                        } catch (error) {
                            console.error(`[PII Extension] Error clearing highlight ${index}:`, error);
                        }
                    });
                }
                
                // Replace redacted items with original text safely
                if (redactedElements.length > 0) {
                    redactedElements.forEach((el, index) => {
                        try {
                            if (el.parentNode && el.parentNode.nodeType === Node.ELEMENT_NODE) {
                                const originalValue = el.getAttribute('data-original-value') || el.textContent;
                                const textNode = document.createTextNode(originalValue);
                                el.parentNode.replaceChild(textNode, el);
                            }
                        } catch (error) {
                            console.error(`[PII Extension] Error clearing redacted element ${index}:`, error);
                        }
                    });
                }
            } catch (error) {
                console.error("[PII Extension] Error processing editor elements:", error);
            }
        }
        
        // Clear overlay highlights safely
        try {
            const overlayElements = document.querySelectorAll('.pii-overlay-highlight');
            overlayElements.forEach((el, index) => {
                try {
                    if (el.parentNode) {
                        el.remove();
                    }
                } catch (error) {
                    console.error(`[PII Extension] Error removing overlay ${index}:`, error);
                }
            });
        } catch (error) {
            console.error("[PII Extension] Error clearing overlays:", error);
        }
        
        // Clear textarea overlay highlights (for Gemini/ChatGPT)
        try {
            const textareaOverlays = document.querySelectorAll('.pii-textarea-overlay');
            textareaOverlays.forEach((el, index) => {
                try {
                    if (el._updatePosition) {
                        window.removeEventListener('scroll', el._updatePosition, true);
                    }
                    if (el.parentNode) {
                        el.remove();
                    }
                } catch (error) {
                    console.error(`[PII Extension] Error removing textarea overlay ${index}:`, error);
                }
            });
        } catch (error) {
            console.error("[PII Extension] Error clearing textarea overlays:", error);
        }
        
        // Clear any open suggestion popups safely
        try {
            document.querySelectorAll(`.${SUGGESTION_POPUP_CLASS}`).forEach((popup, index) => {
                try {
                    if (popup.parentNode) {
                        popup.remove();
                    }
                } catch (error) {
                    console.error(`[PII Extension] Error removing popup ${index}:`, error);
                }
            });
        } catch (error) {
            console.error("[PII Extension] Error clearing popups:", error);
        }
        
        // Reset suggestion states
        suggestionStates.clear();
        
        const totalCleared = textHighlightCount + redactedElements.length;
        
        // Only show alert if explicitly requested and there were highlights to clear
        if (showAlert && totalCleared > 0) {
            alert(`All highlights and redactions cleared. (${textHighlightCount} highlights + ${redactedElements.length} redactions)`);
        } else if (showAlert && totalCleared === 0) {
            alert("No highlights to clear.");
        }
        
        console.log(`[PII Extension] Cleared ${totalCleared} elements successfully`);
    } catch (error) {
        console.error("[PII Extension] Critical error in clearHighlights:", error);
        if (showAlert) {
            alert("An error occurred while clearing highlights. Some elements may remain highlighted.");
        }
    }
}

// Accept all detected PII suggestions automatically
function acceptAllPII() {
    try {
        console.log("[PII Extension] Accept All PII initiated...");
        
        const pageType = detectPageType();
        
        // CRITICAL: For ChatGPT/Gemini, use special non-DOM approach
        if (pageType === 'chatgpt' || pageType === 'gemini') {
            acceptAllPIIForChatGPT();
            return;
        }
        
        // Disable send button during processing if on ChatGPT
        if (pageType === 'chatgpt') {
            toggleChatGPTSendButton(false);
        }
        
        // Get all highlighted PII elements that haven't been processed yet
        const piiHighlights = document.querySelectorAll('.pii-highlight');
        const overlayElements = document.querySelectorAll('[data-pii-overlay]');
        
        let acceptedCount = 0;
        
        // Process regular text highlights safely
        piiHighlights.forEach((highlight, index) => {
            try {
                const piiType = highlight.getAttribute('data-pii-type');
                const piiValue = highlight.getAttribute('data-pii-value');
                
                if (piiType && piiValue) {
                    // Replace with redaction label directly
                    const redactionLabel = getRedactionLabel(piiType);
                    const redactedSpan = document.createElement('span');
                    redactedSpan.textContent = redactionLabel;
                    redactedSpan.style.cssText = `
                        background-color: #22D3EE;
                        color: black;
                        padding: 2px 6px;
                        border-radius: 3px;
                        font-weight: bold;
                        font-size: 12px;
                    `;
                    redactedSpan.setAttribute('data-original-value', piiValue);
                    redactedSpan.setAttribute('data-pii-type', piiType);
                    redactedSpan.classList.add('pii-redacted');
                    
                    // IMPORTANT: Only replace if parent exists and is safe to modify
                    if (highlight.parentNode && highlight.parentNode.nodeType === Node.ELEMENT_NODE) {
                        highlight.parentNode.replaceChild(redactedSpan, highlight);
                        acceptedCount++;
                    } else {
                        console.warn(`[PII Extension] Cannot safely replace highlight ${index}`);
                    }
                }
            } catch (error) {
                console.error(`[PII Extension] Error processing highlight ${index}:`, error);
            }
        });
        
        // Process overlay elements safely
        overlayElements.forEach((overlay, index) => {
            try {
                const piiType = overlay.getAttribute('data-pii-type');
                const piiValue = overlay.getAttribute('data-pii-value');
                
                if (piiType && piiValue) {
                    // Change overlay to show it's redacted
                    const redactionLabel = getRedactionLabel(piiType);
                    overlay.style.backgroundColor = 'rgba(34, 211, 238, 0.9)';
                    overlay.style.border = '2px solid #22D3EE';
                    overlay.innerHTML = `<span style="color: black; font-weight: bold; font-size: 12px; padding: 2px; display: flex; align-items: center; justify-content: center; height: 100%;">${redactionLabel}</span>`;
                    overlay.onclick = null; // Remove click handler
                    overlay.style.cursor = 'default';
                    overlay.title = `Redacted ${piiType}: ${piiValue}`;
                    acceptedCount++;
                }
            } catch (error) {
                console.error(`[PII Extension] Error processing overlay ${index}:`, error);
            }
        });
        
        // Clear any open suggestion popups safely
        try {
            const existingPopup = document.getElementById('pii-suggestion-popup');
            if (existingPopup && existingPopup.parentNode) {
                existingPopup.remove();
            }
        } catch (error) {
            console.error("[PII Extension] Error removing popup:", error);
        }
        
        // Show confirmation
        if (acceptedCount > 0) {
            alert(`Successfully accepted and redacted ${acceptedCount} PII elements.`);
        } else {
            alert("No PII detected to accept. Please scan for PII first.");
        }
        
        console.log(`[PII Extension] Accept All completed. ${acceptedCount} PII elements processed.`);
    } catch (error) {
        console.error("[PII Extension] Critical error in acceptAllPII:", error);
        alert("An error occurred while processing PII. Please try again.");
    }
}

// Handle model selection change
function handleModelChange(event) {
    const selectedModel = event.target.value;
    const previousModel = currentModel;
    currentModel = selectedModel;
    
    console.log(`Model changed from ${previousModel} to ${selectedModel}`);
    
    // Update the dropdown text to show current model
    const modelSelect = document.getElementById('pii-model-select');
    if (modelSelect) {
        // Update the selected option text to show "(Current)"
        Array.from(modelSelect.options).forEach(option => {
            const modelKey = option.value;
            const config = MODEL_CONFIGS[modelKey];
            if (modelKey === selectedModel) {
                option.textContent = `${config.name} (Current)`;
            } else {
                option.textContent = config.name;
            }
        });
    }
    
    // Show model info notification
    const modelConfig = MODEL_CONFIGS[selectedModel];
    const notification = document.createElement('div');
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        left: 50%;
        transform: translateX(-50%);
        background: linear-gradient(135deg, #F0FCFF 0%, rgba(255, 255, 255, 0.95) 100%);
        border: 2px solid #048BA8;
        border-radius: 8px;
        padding: 12px 20px;
        box-shadow: 0 4px 12px rgba(4, 139, 168, 0.3);
        z-index: 1000000;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        font-size: 14px;
        color: #048BA8;
        backdrop-filter: blur(10px);
        animation: slideDown 0.3s ease-out;
    `;
    
    notification.innerHTML = `
        <div style="font-weight: bold; margin-bottom: 4px;">
            ${modelConfig.name} Selected
        </div>
        <div style="font-size: 12px; opacity: 0.8;">
            ${modelConfig.description} • Accuracy: ${modelConfig.accuracy}
        </div>
    `;
    
    document.body.appendChild(notification);
    
    // Remove notification after 3 seconds
    setTimeout(() => {
        if (notification.parentNode) {
            notification.style.animation = 'slideUp 0.3s ease-in';
            setTimeout(() => notification.remove(), 300);
        }
    }, 3000);
    
    // Clear existing highlights since we're switching models
    clearHighlights(false);
    
    // Optionally auto-rescan with new model (commented out for now)
    // setTimeout(() => handleScanClick(), 500);
}


// Handles the Scan button click event
async function handleScanClick() {
  try {
    console.log("[PII Extension] Scan initiated...");
    
    const pageType = detectPageType();
    
    // Disable send button during scanning if on ChatGPT or Gemini
    if (pageType === 'chatgpt' || pageType === 'gemini') {
      if (pageType === 'chatgpt') {
        toggleChatGPTSendButton(false);
      }
      // For Gemini, we don't modify the send button to avoid breaking the UI
    }
    
    // Clear previous highlights silently before starting new scan
    try {
      clearHighlights(false);
    } catch (clearError) {
      console.error("[PII Extension] Error clearing highlights:", clearError);
    }
    
    const editor = findContentArea();
    if (!editor) {
      alert("Content area not found. Please make sure you're on a supported page.");
      
      // Re-enable send button if scan fails
      if (pageType === 'chatgpt') {
        try {
          toggleChatGPTSendButton(true);
        } catch (buttonError) {
          console.error("[PII Extension] Error re-enabling send button after scan failure:", buttonError);
        }
      }
      return;
    }
    
    // Extract text content from the editor
    // For chat interfaces (ChatGPT, Gemini), only get text from input field
    let textToAnalyze = '';
    if (pageType === 'chatgpt' || pageType === 'gemini') {
      // Try multiple selectors for textarea/input fields
      const textareaSelectors = [
        'textarea[aria-label*="prompt"]',
        'textarea[aria-label*="message"]',
        'textarea[placeholder*="prompt"]',
        'textarea[placeholder*="message"]',
        'textarea[contenteditable="true"]',
        'div[contenteditable="true"][role="textbox"]',
        'textarea'
      ];
      
      let textarea = null;
      for (const selector of textareaSelectors) {
        textarea = document.querySelector(selector);
        if (textarea) break;
      }
      
      if (textarea) {
        textToAnalyze = textarea.value || textarea.textContent || '';
        console.log(`[PII Extension] Extracted ${textToAnalyze.length} characters from input field only`);
      } else {
        textToAnalyze = '';
      }
    } else {
      textToAnalyze = editor.textContent || editor.innerText || '';
    }
    
    if (!textToAnalyze.trim()) {
      alert("No text found to analyze. Please type your message in the input field first.");
      if (pageType === 'chatgpt') {
        try {
          toggleChatGPTSendButton(true);
        } catch (buttonError) {
          console.error("[PII Extension] Error re-enabling send button:", buttonError);
        }
      }
      return;
    }
    
    // Show loading indicator
    const scanButton = document.getElementById("pii-scan-button");
    const originalButtonText = scanButton.innerHTML;
    scanButton.innerHTML = `<span role="img" aria-label="Loading">⏳</span> Scanning...`;
    scanButton.disabled = true;
    
    let piiResults;
    try {
      // Try to use backend API first
      const backendAvailable = await checkBackendHealth();
      
      if (backendAvailable) {
        console.log("[PII Extension] Backend available, using Presidio API...");
        piiResults = await detectPIIFromBackend(textToAnalyze, currentModel);
      } else {
        console.warn("[PII Extension] Backend unavailable, using fallback mock data");
        piiResults = getMockPIIData(currentModel);
        alert("⚠️ Backend server not available. Using fallback mode. Please ensure the backend server is running on http://127.0.0.1:5000");
      }
    } catch (error) {
      console.error("[PII Extension] Error detecting PII:", error);
      // Fallback to mock data on error
      piiResults = getMockPIIData(currentModel);
      alert("⚠️ Error connecting to backend. Using fallback mode. Please check if the backend server is running.");
    } finally {
      // Restore button
      scanButton.innerHTML = originalButtonText;
      scanButton.disabled = false;
    }
    
    // Process results and highlight
    if (piiResults && piiResults.detected_entities && piiResults.detected_entities.length > 0) {
        const modelName = MODEL_CONFIGS[currentModel]?.name || currentModel;
        alert(`Scan complete with ${modelName}! ${piiResults.total_entities} PII suggestions found. Click highlighted text to review and accept/reject each suggestion.`);
        
        try {
          highlightPiiInDocument(piiResults.detected_entities);
        } catch (highlightError) {
          console.error("[PII Extension] Error highlighting PII:", highlightError);
          alert("PII detected but highlighting failed. Please try again.");
        }
        
        // Re-enable send button after highlighting is complete
        if (pageType === 'chatgpt') {
          setTimeout(() => {
            try {
              toggleChatGPTSendButton(true);
            } catch (buttonError) {
              console.error("[PII Extension] Error re-enabling send button after highlighting:", buttonError);
            }
          }, 500);
        }
    } else {
        const modelName = MODEL_CONFIGS[currentModel]?.name || currentModel;
        alert(`Scan complete with ${modelName}, no PII found.`);
        
        // Re-enable send button if no PII found
        if (pageType === 'chatgpt') {
          try {
            toggleChatGPTSendButton(true);
          } catch (buttonError) {
            console.error("[PII Extension] Error re-enabling send button after no PII found:", buttonError);
          }
        }
    }
  } catch (error) {
    console.error("[PII Extension] Critical error in handleScanClick:", error);
    
    // Always try to re-enable send button in case of errors
    try {
      const pageType = detectPageType();
      if (pageType === 'chatgpt') {
        toggleChatGPTSendButton(true);
      }
      // For Gemini, we don't modify the send button
      // Restore button
      const scanButton = document.getElementById("pii-scan-button");
      if (scanButton) {
        scanButton.innerHTML = `<span role="img" aria-label="Shield">🛡️</span> Scan for PII`;
        scanButton.disabled = false;
      }
    } catch (buttonError) {
      console.error("[PII Extension] Error re-enabling send button after critical error:", buttonError);
    }
    
    alert("An error occurred during scanning. Please try again.");
  }
}

// The core function to highlight PII using safe regex-based HTML replacement
function highlightPiiInDocument(entities) {
    const pageType = detectPageType();
    
    // CRITICAL: For ChatGPT and Gemini, use special approach that only highlights in input field
    if (pageType === 'chatgpt' || pageType === 'gemini') {
        console.log(`[PII Extension] Using ${pageType === 'gemini' ? 'Gemini' : 'ChatGPT'}-safe highlighting approach`);
        highlightPiiForChatGPT(entities);
        return;
    }
    
    // Original approach for other platforms
    const editor = findContentArea();
    if (!editor) {
        console.warn("Cannot highlight PII: Content area not found");
        return;
    }

    console.log("Starting regex-based PII highlighting process...");
    console.log("Editor element:", editor);

    let highlightCount = 0;

    // Check if editor HTML already contains highlights to avoid nested highlighting
    if (editor.innerHTML.includes(HIGHLIGHT_CLASS)) {
        console.log("Editor already contains highlights, clearing first...");
        clearHighlights(false);
    }

    // Get the current HTML content
    let currentHTML = editor.innerHTML;
    console.log("Original HTML length:", currentHTML.length);

    // Sort entities by length (longest first) to avoid partial matches
    const sortedEntities = entities.sort((a, b) => b.value.length - a.value.length);
    
    sortedEntities.forEach(entity => {
        console.log(`Processing PII: "${entity.value}" (${entity.type})`);
        
        // Escape special regex characters in the entity value
        const escapedValue = entity.value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        
        // Create regex with word boundaries for exact matching
        // Use \b for word boundaries, but make it flexible for non-English characters
        const regex = new RegExp(`(?<!<[^>]*)(${escapedValue})(?![^<]*>)`, 'gi');
        
        // Create the highlight HTML structure with suggestion functionality
        const highlightHTML = `<span class="${HIGHLIGHT_CLASS}" data-pii-type="${entity.type}" data-pii-value="${entity.value}" data-suggestion-id="${generateSuggestionId()}">$1</span>`;
        
        // Count matches before replacement
        const matches = currentHTML.match(regex);
        const matchCount = matches ? matches.length : 0;
        
        if (matchCount > 0) {
            console.log(`Found ${matchCount} instances of "${entity.value}"`);
            
            // Perform the replacement
            currentHTML = currentHTML.replace(regex, highlightHTML);
            highlightCount += matchCount;
            
            console.log(`✅ Highlighted ${matchCount} instances of "${entity.value}"`);
        } else {
            console.log(`❌ No instances found for "${entity.value}"`);
        }
    });

    // Apply the modified HTML back to the editor
    if (highlightCount > 0) {
        try {
            editor.innerHTML = currentHTML;
            console.log(`Successfully applied highlights. Total: ${highlightCount} instances`);
            
            // Add click events to the newly created highlight spans
            addRedactEvents();
            
            alert(`Highlighting complete! Found ${highlightCount} PII suggestions. Click any highlighted text to review and accept/reject.`);
        } catch (error) {
            console.error("Error applying HTML changes:", error);
            
            // Fallback to overlay system if HTML modification fails
            console.log("HTML modification failed, falling back to overlay system...");
            highlightWithOverlay(entities);
        }
    } else {
        console.warn("No PII could be highlighted with regex method");
        
        // Check if PII exists in the text content at all
        const textContent = editor.textContent || editor.innerText || '';
        const foundInText = entities.some(entity => 
            textContent.toLowerCase().includes(entity.value.toLowerCase())
        );
        
        if (foundInText) {
            console.log("PII found in text but not highlighted, trying overlay system...");
            highlightWithOverlay(entities);
        } else {
            alert("No PII found to highlight. Make sure your document contains the sample text.");
        }
    }
}

// ChatGPT/Gemini-specific highlighting that shows inline highlights in the input field
function highlightPiiForChatGPT(entities) {
    try {
        const pageType = detectPageType();
        const isGemini = pageType === 'gemini';
        
        // Try multiple selectors to find the input field
        const textareaSelectors = [
            'textarea[aria-label*="prompt"]',
            'textarea[aria-label*="message"]',
            'textarea[placeholder*="prompt"]',
            'textarea[placeholder*="message"]',
            'textarea[contenteditable="true"]',
            'div[contenteditable="true"][role="textbox"]',
            'textarea'
        ];
        
        let textarea = null;
        for (const selector of textareaSelectors) {
            textarea = document.querySelector(selector);
            if (textarea) {
                console.log(`[PII Extension] Found input field with selector: ${selector}`);
                break;
            }
        }
        
        if (!textarea) {
            console.warn(`[PII Extension] ${isGemini ? 'Gemini' : 'ChatGPT'} input field not found`);
            alert(`${isGemini ? 'Gemini' : 'ChatGPT'} input not found. Please make sure you're in the chat interface.`);
            return;
        }
        
        // Get text from input field (handle both textarea.value and contenteditable divs)
        const originalText = textarea.value || textarea.textContent || '';
        if (!originalText.trim()) {
            alert(`No text found in ${isGemini ? 'Gemini' : 'ChatGPT'} input. Please type your message in the input field first.`);
            return;
        }
        
        console.log(`[PII Extension] Analyzing ${isGemini ? 'Gemini' : 'ChatGPT'} input field text for PII (${originalText.length} characters)...`);
        
        // First, filter out any PII that overlaps with already-redacted text
        const filteredEntities = filterRedactedPII(entities, originalText);
        console.log(`[PII Extension] Filtered ${entities.length - filteredEntities.length} PII entities that overlap with redacted text`);
        
        // Find PII in the text by searching for each entity value in the current text
        // This ensures we find the actual positions, even if text has changed
        const foundPII = [];
        filteredEntities.forEach(entity => {
            const entityValue = entity.value;
            const entityType = entity.type;
            
            // Search for this entity value in the current text
            // Use case-insensitive search to handle variations
            const lowerText = originalText.toLowerCase();
            const lowerEntityValue = entityValue.toLowerCase();
            
            // Find all occurrences of this entity in the text
            let searchIndex = 0;
            const occurrences = [];
            
            while (true) {
                const foundIndex = lowerText.indexOf(lowerEntityValue, searchIndex);
                if (foundIndex === -1) break;
                
                // Get the actual text at this position
                const actualText = originalText.substring(foundIndex, foundIndex + entityValue.length);
                
                // Verify it matches (case-insensitive)
                if (actualText.toLowerCase() === lowerEntityValue) {
                    // Check if this position is already redacted
                    if (!isRedactedText(originalText, foundIndex, foundIndex + entityValue.length)) {
                        occurrences.push({
                            start: foundIndex,
                            end: foundIndex + entityValue.length,
                            value: actualText
                        });
                    }
                }
                
                searchIndex = foundIndex + 1;
            }
            
            // Add all found occurrences as separate PII entities
            occurrences.forEach(occurrence => {
                foundPII.push({
                    type: entityType,
                    start: occurrence.start,
                    end: occurrence.end,
                    value: occurrence.value,
                    confidence: entity.confidence || 0.9
                });
                console.log(`[PII Extension] Found PII "${occurrence.value}" at ${occurrence.start}-${occurrence.end}`);
            });
            
            if (occurrences.length === 0) {
                console.warn(`[PII Extension] Could not find PII "${entityValue}" in current text (may be redacted or modified)`);
            }
        });
        
        if (foundPII.length === 0) {
            alert(`No PII found in your ${isGemini ? 'Gemini' : 'ChatGPT'} message.`);
            return;
        }
        
        // Store the original text and PII info for later use
        window.chatGPTOriginalText = originalText;
        window.chatGPTFoundPII = foundPII;
        window.chatGPTTextarea = textarea;
        
        // Create inline overlay highlights for each PII item
        createInlineHighlightsForTextarea(textarea, foundPII, originalText);
        
        // Show info message
        alert(`Found ${foundPII.length} PII items in your input. Click any yellow highlight to accept or reject individually.`);
        
    } catch (error) {
        console.error("[PII Extension] Error in chat interface PII analysis:", error);
        const pageType = detectPageType();
        alert(`Error analyzing ${pageType === 'gemini' ? 'Gemini' : 'ChatGPT'} text. Please try again.`);
    }
}

// NEW ROBUST HIGHLIGHTING SYSTEM
// Creates accurate highlights by finding actual text positions and handling multi-line text properly
function createInlineHighlightsForTextarea(textarea, entities, text) {
    // Remove any existing highlights first
    document.querySelectorAll('.pii-textarea-overlay').forEach(el => {
        if (el._updatePosition) {
            window.removeEventListener('scroll', el._updatePosition, true);
            window.removeEventListener('resize', el._updatePosition);
        }
        el.remove();
    });
    
    const textareaRect = textarea.getBoundingClientRect();
    const textareaStyle = window.getComputedStyle(textarea);
    const lineHeight = parseFloat(textareaStyle.lineHeight) || parseFloat(textareaStyle.fontSize) * 1.2;
    
    // Sort entities by position
    const sortedEntities = entities.sort((a, b) => a.start - b.start);
    
    sortedEntities.forEach((entity, index) => {
        try {
            const entityText = text.substring(entity.start, entity.end);
            
            // Use new robust positioning method
            const lineSegments = getTextLineSegments(textarea, text, entity.start, entity.end, textareaRect, textareaStyle);
            
            if (lineSegments.length === 0) {
                console.warn(`[PII Extension] Could not find line segments for "${entity.value}"`);
                return;
            }
            
            // Create a highlight overlay for each line segment
            // This ensures accurate highlighting even for multi-line text
            lineSegments.forEach((segment, segIndex) => {
                const overlay = createHighlightOverlay(segment, entity, textareaRect, textareaStyle, segIndex === 0);
                
                // Store reference to entity for click handling
                overlay._entity = entity;
                overlay._allSegments = lineSegments;
                overlay._segmentIndex = segIndex;
                
                document.body.appendChild(overlay);
                
                // Setup position update handler
                setupOverlayPositionUpdate(overlay, textarea, entity, text, textareaRect, textareaStyle);
            });
            
            console.log(`[PII Extension] Created ${lineSegments.length} overlay(s) for "${entity.value}"`);
        } catch (error) {
            console.error(`[PII Extension] Error creating overlay for entity ${index}:`, error);
        }
    });
    
    console.log(`[PII Extension] Created highlights for ${sortedEntities.length} entities`);
}

// Get line segments for text that may wrap across multiple lines
// Uses precise Range API to get exact character positions
// Returns array of {left, top, width, height} for each line segment
function getTextLineSegments(textarea, fullText, start, end, textareaRect, textareaStyle) {
    const segments = [];
    
    // Validate indices
    if (start < 0 || end < start || end > fullText.length) {
        console.warn(`[PII Extension] Invalid indices: start=${start}, end=${end}, textLength=${fullText.length}`);
        return segments;
    }
    
    // Create a perfect mirror of the textarea
    const mirror = createTextareaMirror(textarea, textareaRect, textareaStyle);
    document.body.appendChild(mirror);
    
    try {
        const textBefore = fullText.substring(0, start);
        const entityText = fullText.substring(start, end);
        const textAfter = fullText.substring(end);
        
        // Build mirror content with text nodes
        mirror.innerHTML = '';
        const beforeNode = textBefore ? document.createTextNode(textBefore) : null;
        const entityNode = document.createTextNode(entityText);
        const afterNode = textAfter ? document.createTextNode(textAfter) : null;
        
        if (beforeNode) mirror.appendChild(beforeNode);
        mirror.appendChild(entityNode);
        if (afterNode) mirror.appendChild(afterNode);
        
        // Force layout calculation
        void mirror.offsetHeight;
        
        // Use Range API to get precise positions
        const range = document.createRange();
        const fontSize = parseFloat(textareaStyle.fontSize) || 14;
        const lineHeightValue = parseFloat(textareaStyle.lineHeight) || fontSize * 1.2;
        
        try {
            // Set range to exactly cover the entity text
            range.setStart(entityNode, 0);
            range.setEnd(entityNode, entityText.length);
            
            // Get all client rects (one per line for wrapped text)
            const rangeRects = range.getClientRects();
            
            if (rangeRects.length === 0) {
                // Fallback: use bounding rect
                const boundingRect = range.getBoundingClientRect();
                if (boundingRect.width > 0 && boundingRect.height > 0) {
                    segments.push({
                        left: boundingRect.left,
                        top: boundingRect.top,
                        width: boundingRect.width,
                        height: boundingRect.height
                    });
                }
            } else {
                // Process each rect (each represents a line segment)
                for (let i = 0; i < rangeRects.length; i++) {
                    const rect = rangeRects[i];
                    
                    // Only add valid rects
                    if (rect.width > 0 && rect.height > 0) {
                        segments.push({
                            left: rect.left,
                            top: rect.top,
                            width: rect.width,
                            height: rect.height
                        });
                    }
                }
                
                // If we got multiple rects but they're on the same line, merge them
                if (segments.length > 1) {
                    const merged = [];
                    let current = null;
                    
                    segments.forEach(seg => {
                        if (!current || Math.abs(seg.top - current.top) > lineHeightValue * 0.3) {
                            // New line
                            if (current) merged.push(current);
                            current = { ...seg };
                        } else {
                            // Same line - extend width
                            current.width = seg.left + seg.width - current.left;
                            current.height = Math.max(current.height, seg.height);
                        }
                    });
                    
                    if (current) merged.push(current);
                    return merged;
                }
            }
        } catch (e) {
            console.warn('[PII Extension] Range API error, using fallback:', e);
            // Fallback: use entity node's bounding rect
            const entityRect = entityNode.parentElement ? 
                entityNode.parentElement.getBoundingClientRect() : 
                mirror.getBoundingClientRect();
            
            if (entityRect.width > 0) {
                segments.push({
                    left: entityRect.left,
                    top: entityRect.top,
                    width: entityRect.width,
                    height: entityRect.height || lineHeightValue
                });
            }
        }
        
    } finally {
        // Clean up mirror
        try {
            document.body.removeChild(mirror);
        } catch (e) {
            console.warn('[PII Extension] Error removing mirror:', e);
        }
    }
    
    return segments;
}

// Create a perfect mirror of the textarea for measurement
function createTextareaMirror(textarea, textareaRect, textareaStyle) {
    const mirror = document.createElement('div');
    mirror.style.position = 'fixed';
    mirror.style.visibility = 'hidden';
    mirror.style.whiteSpace = 'pre-wrap';
    mirror.style.wordWrap = 'break-word';
    mirror.style.wordBreak = textareaStyle.wordBreak || 'normal';
    mirror.style.fontSize = textareaStyle.fontSize;
    mirror.style.fontFamily = textareaStyle.fontFamily;
    mirror.style.fontWeight = textareaStyle.fontWeight;
    mirror.style.fontStyle = textareaStyle.fontStyle;
    mirror.style.letterSpacing = textareaStyle.letterSpacing;
    mirror.style.lineHeight = textareaStyle.lineHeight;
    mirror.style.width = textareaRect.width + 'px';
    mirror.style.padding = textareaStyle.padding;
    mirror.style.border = textareaStyle.border;
    mirror.style.boxSizing = 'border-box';
    mirror.style.overflow = 'visible';
    mirror.style.left = textareaRect.left + 'px';
    mirror.style.top = textareaRect.top + 'px';
    mirror.style.zIndex = '-9999';
    return mirror;
}

// Create a single highlight overlay element
function createHighlightOverlay(segment, entity, textareaRect, textareaStyle, isFirstSegment) {
    const overlay = document.createElement('div');
    overlay.className = 'pii-textarea-overlay';
    overlay.setAttribute('data-pii-type', entity.type);
    overlay.setAttribute('data-pii-value', entity.value);
    overlay.setAttribute('data-pii-start', entity.start);
    overlay.setAttribute('data-pii-end', entity.end);
    overlay.setAttribute('data-suggestion-id', generateSuggestionId());
    
    // Ensure segment is within textarea bounds
    let left = Math.max(segment.left, textareaRect.left);
    let top = Math.max(segment.top, textareaRect.top);
    let width = Math.min(segment.width, textareaRect.right - left);
    let height = Math.max(segment.height, 16);
    
    // Ensure minimum dimensions
    width = Math.max(width, 20);
    
    overlay.style.position = 'fixed';
    overlay.style.left = left + 'px';
    overlay.style.top = top + 'px';
    overlay.style.width = width + 'px';
    overlay.style.height = height + 'px';
    overlay.style.backgroundColor = 'rgba(251, 191, 36, 0.6)';
    overlay.style.border = '2px solid #F59E0B';
    overlay.style.borderRadius = '3px';
    overlay.style.pointerEvents = 'auto';
    overlay.style.cursor = 'pointer';
    overlay.style.zIndex = '999999';
    overlay.style.boxSizing = 'border-box';
    overlay.style.transition = 'all 0.2s ease';
    overlay.style.overflow = 'hidden';
    
    // Hover effects
    overlay.onmouseenter = () => {
        overlay.style.backgroundColor = 'rgba(251, 191, 36, 0.9)';
    };
    overlay.onmouseleave = () => {
        overlay.style.backgroundColor = 'rgba(251, 191, 36, 0.6)';
    };
    
    // Click handler - use the first segment's entity for the popup
    overlay.onclick = (event) => {
        event.stopPropagation();
        event.preventDefault();
        if (isFirstSegment && overlay._entity) {
            showTextareaSuggestionPopup(overlay, overlay._entity);
        }
    };
    
    overlay.title = `Click to review ${entity.type}: "${entity.value}"`;
    
    return overlay;
}

// ============================================================================
// OFFSET TRACKING SYSTEM FOR PII REDACTION
// ============================================================================

/**
 * Option A: Replace spans in descending order (from end to start)
 * This prevents earlier spans' indices from shifting when later ones are replaced.
 * 
 * @param {string} text - Original text string
 * @param {Array} spans - Array of {start, end, entity} objects with original offsets
 * @param {Function} maskFor - Callback that returns mask string for given entity
 * @returns {Object} {text: redactedText, updatedSpans: array with new offsets}
 */
function redactPII_DescendingOrder(text, spans, maskFor) {
    // Sort spans by start position in descending order
    const sortedSpans = [...spans].sort((a, b) => b.start - a.start);
    
    let redactedText = text;
    const updatedSpans = [];
    
    // Track offset adjustments for each span
    const adjustments = new Map();
    
    sortedSpans.forEach(span => {
        const mask = maskFor(span.entity);
        const originalLength = span.end - span.start;
        const lengthDiff = mask.length - originalLength;
        
        // Apply redaction
        redactedText = redactedText.substring(0, span.start) + mask + redactedText.substring(span.end);
        
        // Calculate new offsets for this span
        const newStart = span.start;
        const newEnd = span.start + mask.length;
        
        updatedSpans.push({
            start: newStart,
            end: newEnd,
            entity: span.entity,
            maskedText: mask
        });
        
        // Store adjustment for spans that come before this one
        adjustments.set(span.start, lengthDiff);
    });
    
    // Update offsets for all spans based on adjustments
    updatedSpans.forEach(span => {
        let adjustment = 0;
        adjustments.forEach((diff, position) => {
            if (position > span.start) {
                adjustment += diff;
            }
        });
        
        if (adjustment !== 0) {
            span.start += adjustment;
            span.end += adjustment;
        }
    });
    
    // Sort updated spans back to ascending order
    updatedSpans.sort((a, b) => a.start - b.start);
    
    return {
        text: redactedText,
        updatedSpans: updatedSpans
    };
}

/**
 * Option B: Replace spans in ascending order with delta tracking
 * Tracks cumulative length difference as we process each span.
 * 
 * @param {string} text - Original text string
 * @param {Array} spans - Array of {start, end, entity} objects with original offsets
 * @param {Function} maskFor - Callback that returns mask string for given entity
 * @returns {Object} {text: redactedText, updatedSpans: array with new offsets}
 */
function redactPII_AscendingOrder(text, spans, maskFor) {
    // Sort spans by start position in ascending order
    const sortedSpans = [...spans].sort((a, b) => a.start - b.start);
    
    let redactedText = text;
    let cumulativeDelta = 0; // Track cumulative length difference
    const updatedSpans = [];
    
    sortedSpans.forEach(span => {
        const mask = maskFor(span.entity);
        const originalLength = span.end - span.start;
        const lengthDiff = mask.length - originalLength;
        
        // Adjust start/end positions based on previous redactions
        const adjustedStart = span.start + cumulativeDelta;
        const adjustedEnd = span.end + cumulativeDelta;
        
        // Apply redaction at adjusted position
        redactedText = redactedText.substring(0, adjustedStart) + 
                      mask + 
                      redactedText.substring(adjustedEnd);
        
        // Calculate new offsets
        const newStart = adjustedStart;
        const newEnd = adjustedStart + mask.length;
        
        updatedSpans.push({
            start: newStart,
            end: newEnd,
            entity: span.entity,
            maskedText: mask
        });
        
        // Update cumulative delta for next iterations
        cumulativeDelta += lengthDiff;
    });
    
    return {
        text: redactedText,
        updatedSpans: updatedSpans
    };
}

/**
 * Main redaction function - uses Option B (ascending order) by default
 * as it's more intuitive and easier to understand.
 */
function redactPIIWithOffsetTracking(text, spans, maskFor) {
    return redactPII_AscendingOrder(text, spans, maskFor);
}

// ============================================================================
// END OFFSET TRACKING SYSTEM
// ============================================================================

// Setup position update handler for overlay
function setupOverlayPositionUpdate(overlay, textarea, entity, originalText, textareaRect, textareaStyle) {
    const updatePosition = () => {
        try {
            const currentText = textarea.value || textarea.textContent || originalText;
            const newRect = textarea.getBoundingClientRect();
            
            // Recalculate segments if text hasn't changed much
            if (Math.abs(currentText.length - originalText.length) < 10) {
                const segments = getTextLineSegments(textarea, currentText, entity.start, entity.end, newRect, textareaStyle);
                
                if (segments.length > 0 && overlay._segmentIndex < segments.length) {
                    const segment = segments[overlay._segmentIndex];
                    
                    let left = Math.max(segment.left, newRect.left);
                    let top = Math.max(segment.top, newRect.top);
                    let width = Math.min(segment.width, newRect.right - left);
                    let height = Math.max(segment.height, 16);
                    
                    width = Math.max(width, 20);
                    
                    overlay.style.left = left + 'px';
                    overlay.style.top = top + 'px';
                    overlay.style.width = width + 'px';
                    overlay.style.height = height + 'px';
                }
            }
        } catch (e) {
            console.warn('[PII Extension] Error updating overlay position:', e);
        }
    };
    
    window.addEventListener('scroll', updatePosition, true);
    window.addEventListener('resize', updatePosition);
    overlay._updatePosition = updatePosition;
}

// Helper function to calculate text position using a mirror element with accurate word wrapping
function calculateTextPosition(textarea, fullText, start, end, textareaRect, textareaStyle) {
    const paddingLeft = parseFloat(textareaStyle.paddingLeft) || 0;
    const paddingTop = parseFloat(textareaStyle.paddingTop) || 0;
    const fontSize = parseFloat(textareaStyle.fontSize) || 14;
    const fontFamily = textareaStyle.fontFamily;
    const lineHeight = parseFloat(textareaStyle.lineHeight) || fontSize * 1.2;
    const borderWidth = parseFloat(textareaStyle.borderLeftWidth) || 0;
    
    // Validate indices
    if (start < 0 || end < start || end > fullText.length) {
        console.warn(`[PII Extension] Invalid text indices: start=${start}, end=${end}, textLength=${fullText.length}`);
        return { left: 0, top: 0, width: 0, height: lineHeight };
    }
    
    // Create a mirror div with same styling as textarea, positioned exactly like textarea
    const mirror = document.createElement('div');
    mirror.style.position = 'fixed';
    mirror.style.visibility = 'hidden';
    mirror.style.whiteSpace = 'pre-wrap';
    mirror.style.wordWrap = 'break-word';
    mirror.style.wordBreak = textareaStyle.wordBreak || 'normal';
    mirror.style.fontSize = fontSize + 'px';
    mirror.style.fontFamily = fontFamily;
    mirror.style.fontWeight = textareaStyle.fontWeight;
    mirror.style.fontStyle = textareaStyle.fontStyle;
    mirror.style.letterSpacing = textareaStyle.letterSpacing;
    mirror.style.lineHeight = textareaStyle.lineHeight;
    mirror.style.width = textareaRect.width + 'px';
    mirror.style.padding = textareaStyle.padding;
    mirror.style.border = textareaStyle.border;
    mirror.style.boxSizing = 'border-box';
    mirror.style.overflow = 'hidden';
    mirror.style.left = textareaRect.left + 'px';
    mirror.style.top = textareaRect.top + 'px';
    mirror.style.zIndex = '-9999'; // Ensure it's behind everything
    document.body.appendChild(mirror);
    
    const textBefore = fullText.substring(0, start);
    const entityText = fullText.substring(start, end);
    const textAfter = fullText.substring(end);
    
    // Use marker spans to measure exact positions
    const startMarker = document.createElement('span');
    startMarker.id = 'pii-start-marker-' + Date.now();
    startMarker.style.display = 'inline';
    startMarker.style.width = '0';
    startMarker.style.height = '0';
    startMarker.style.overflow = 'hidden';
    
    const endMarker = document.createElement('span');
    endMarker.id = 'pii-end-marker-' + Date.now();
    endMarker.style.display = 'inline';
    endMarker.style.width = '0';
    endMarker.style.height = '0';
    endMarker.style.overflow = 'hidden';
    
    // Build mirror content with markers - use text nodes to preserve exact formatting
    mirror.innerHTML = '';
    if (textBefore) {
        mirror.appendChild(document.createTextNode(textBefore));
    }
    mirror.appendChild(startMarker);
    if (entityText) {
        mirror.appendChild(document.createTextNode(entityText));
    }
    mirror.appendChild(endMarker);
    if (textAfter) {
        mirror.appendChild(document.createTextNode(textAfter));
    }
    
    // Force a reflow to ensure layout is calculated
    void mirror.offsetHeight;
    
    // Get positions of markers
    const startRect = startMarker.getBoundingClientRect();
    const endRect = endMarker.getBoundingClientRect();
    
    // Check if text spans multiple lines (wrapped text)
    // Compare Y positions - if they differ significantly, text wraps
    const lineHeightValue = parseFloat(textareaStyle.lineHeight) || fontSize * 1.2;
    const spansMultipleLines = Math.abs(startRect.top - endRect.top) > lineHeightValue * 0.3;
    
    let left, top, width, height;
    
    if (spansMultipleLines) {
        // Text wraps across multiple lines
        // For multi-line text, we need to be more careful with width calculation
        // The issue is that a single rectangle can't perfectly represent wrapped text
        // So we'll calculate a reasonable bounding box
        
        left = startRect.left;
        top = startRect.top;
        
        // Calculate the number of lines
        const numLines = Math.ceil((endRect.bottom - startRect.top) / lineHeightValue);
        
        // For multi-line text, calculate width more carefully
        // First line: from start to right edge (or to end if it fits on one line)
        // Last line: from left edge to end
        const firstLineRemaining = textareaRect.right - startRect.left;
        const lastLineWidth = endRect.right - textareaRect.left;
        
        if (numLines === 2) {
            // Two lines: use the maximum width needed
            // But don't make it wider than necessary
            width = Math.max(firstLineRemaining, lastLineWidth);
            // Cap it at textarea width to avoid over-extending
            width = Math.min(width, textareaRect.width);
        } else {
            // Three or more lines: middle lines need full width
            // But we still need to cover first and last lines properly
            width = textareaRect.width;
            // But if the calculated width from markers is reasonable, use that instead
            const markerWidth = endRect.right - startRect.left;
            if (markerWidth < textareaRect.width * 1.5 && markerWidth > 0) {
                width = Math.max(markerWidth, Math.max(firstLineRemaining, lastLineWidth));
            }
        }
        
        // Height spans from first line top to last line bottom
        height = endRect.bottom - startRect.top;
        
        // Ensure minimum dimensions
        if (height < lineHeightValue) {
            height = lineHeightValue;
        }
        if (width <= 0) {
            width = 20; // Minimum width
        }
        
        console.log(`[PII Extension] Multi-line text "${entityText.substring(0, 30)}": ${numLines} lines, width=${width.toFixed(1)}, height=${height.toFixed(1)}`);
    } else {
        // Single line - use marker positions directly
        left = startRect.left;
        top = startRect.top;
        width = Math.max(endRect.right - startRect.left, 10);
        height = Math.max(endRect.bottom - startRect.top, lineHeight);
    }
    
    // Ensure width is not negative or zero
    if (width <= 0) {
        // Fallback: estimate width based on text length
        const canvas = document.createElement('canvas');
        const context = canvas.getContext('2d');
        context.font = `${fontSize}px ${fontFamily}`;
        width = Math.max(context.measureText(entityText).width, 20);
    }
    
    // Ensure height is reasonable (for multi-line, should be at least lineHeight)
    if (height <= 0) {
        height = spansMultipleLines ? lineHeight * Math.ceil(entityText.length / 50) : lineHeight;
    }
    
    // Clean up
    try {
        document.body.removeChild(mirror);
    } catch (e) {
        console.warn('[PII Extension] Error removing mirror element:', e);
    }
    
    return { left, top, width, height };
}

// Helper function to find text node at a specific character position
function findTextNodeAtPosition(element, charPosition) {
    let currentPos = 0;
    const walker = document.createTreeWalker(
        element,
        NodeFilter.SHOW_TEXT,
        null
    );
    
    let node;
    while (node = walker.nextNode()) {
        const nodeLength = node.textContent.length;
        if (currentPos + nodeLength >= charPosition) {
            return node;
        }
        currentPos += nodeLength;
    }
    return null;
}

// Show suggestion popup for textarea overlay highlights
function showTextareaSuggestionPopup(overlayElement, entity) {
    // Remove any existing popups
    document.querySelectorAll(`.${SUGGESTION_POPUP_CLASS}`).forEach(popup => popup.remove());
    
    const piiValue = overlayElement.getAttribute('data-pii-value');
    const piiType = overlayElement.getAttribute('data-pii-type');
    const suggestionId = overlayElement.getAttribute('data-suggestion-id');
    
    // Create popup
    const popup = document.createElement('div');
    popup.className = SUGGESTION_POPUP_CLASS;
    
    // Position popup near the overlay
    const rect = overlayElement.getBoundingClientRect();
    popup.style.left = Math.min(rect.left, window.innerWidth - 440) + 'px';
    popup.style.top = (rect.bottom + 10) + 'px';
    
    // Create popup content
    popup.innerHTML = `
        <div style="margin-bottom: 12px;">
            <strong>PII Detected</strong>
        </div>
        <div style="margin-bottom: 8px;">
            <strong>Type:</strong> ${piiType}
        </div>
        <div style="margin-bottom: 8px;">
            <strong>Value:</strong> "<span class="pii-value-highlight">${piiValue}</span>"
        </div>
        <div style="margin-bottom: 16px;">
            <strong>Will become:</strong> "<span class="pii-redaction-preview">${getRedactionLabel(piiType)}</span>"
        </div>
        <div style="display: flex; gap: 10px; justify-content: flex-end;">
            <button id="reject-textarea-btn">✕ Reject</button>
            <button id="accept-textarea-btn">✓ Accept</button>
        </div>
    `;
    
    document.body.appendChild(popup);
    
    // Add event listeners
    popup.querySelector('#accept-textarea-btn').onclick = () => acceptTextareaSuggestion(overlayElement, entity, suggestionId, popup);
    popup.querySelector('#reject-textarea-btn').onclick = () => rejectTextareaSuggestion(overlayElement, suggestionId, popup);
    
    // Close popup when clicking outside
    const closePopup = (event) => {
        if (!popup.contains(event.target) && !overlayElement.contains(event.target)) {
            popup.remove();
            document.removeEventListener('click', closePopup);
        }
    };
    
    setTimeout(() => {
        document.addEventListener('click', closePopup);
    }, 100);
}

// Accept individual PII suggestion in textarea
function acceptTextareaSuggestion(overlayElement, entity, suggestionId, popup) {
    const textarea = window.chatGPTTextarea;
    if (!textarea) {
        alert("Input field not found. Please try scanning again.");
        popup.remove();
        return;
    }
    
    // Get current text from textarea (may have been modified)
    const currentText = textarea.value || textarea.textContent || '';
    const piiValue = overlayElement.getAttribute('data-pii-value');
    const piiType = overlayElement.getAttribute('data-pii-type');
    const redactionLabel = getRedactionLabel(piiType);
    
    // Get the stored start/end positions
    const start = parseInt(overlayElement.getAttribute('data-pii-start'));
    const end = parseInt(overlayElement.getAttribute('data-pii-end'));
    
    // Verify the text at this position matches what we expect
    const textAtPosition = currentText.substring(start, end);
    console.log(`[PII Extension] Verifying redaction: expected "${piiValue}" at ${start}-${end}, found "${textAtPosition}"`);
    
    // Replace using offsets - but verify first
    let newText;
    const actualTextAtOffset = currentText.substring(start, end);
    
    // Check if the text at the offset matches what we expect
    if (actualTextAtOffset === piiValue || actualTextAtOffset.toLowerCase() === piiValue.toLowerCase()) {
        // Offsets are correct, use them directly
        newText = currentText.substring(0, start) + redactionLabel + currentText.substring(end);
        console.log(`[PII Extension] Redacting using verified offsets: ${start}-${end}`);
    } else {
        // Offsets don't match - the text may have been modified
        // Try to find the exact PII value in the text
        console.warn(`[PII Extension] Offset mismatch. Searching for "${piiValue}" in text...`);
        
        // Escape special regex characters
        const escapedPii = piiValue.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        const regex = new RegExp(escapedPii, 'gi');
        const matches = [...currentText.matchAll(regex)];
        
        if (matches.length > 0) {
            // Find the match closest to the expected position
            let bestMatch = matches[0];
            let minDistance = Math.abs(matches[0].index - start);
            
            for (const match of matches) {
                const distance = Math.abs(match.index - start);
                if (distance < minDistance) {
                    minDistance = distance;
                    bestMatch = match;
                }
            }
            
            const foundIndex = bestMatch.index;
            const foundLength = bestMatch[0].length;
            console.log(`[PII Extension] Found PII at adjusted position: ${foundIndex} (expected ${start}), length: ${foundLength}`);
            
            newText = currentText.substring(0, foundIndex) + redactionLabel + currentText.substring(foundIndex + foundLength);
            
            // Update the stored offsets for this redaction
            const adjustedStart = foundIndex;
            const adjustedEnd = foundIndex + foundLength;
            
            // Update the overlay's stored offsets for recalculation
            overlayElement.setAttribute('data-pii-start', adjustedStart);
            overlayElement.setAttribute('data-pii-end', adjustedEnd);
        } else {
            console.error(`[PII Extension] Could not find PII "${piiValue}" in current text`);
            alert(`Error: Could not find "${piiValue}" in the text. The text may have been modified.`);
            popup.remove();
            return;
        }
    }
    
    // Update the stored original text
    window.chatGPTOriginalText = newText;
    
    // Update the textarea
    if (textarea.tagName === 'TEXTAREA') {
        textarea.value = newText;
    } else {
        textarea.textContent = newText;
    }
    
    // Trigger events
    const inputEvent = new Event("input", { bubbles: true });
    textarea.dispatchEvent(inputEvent);
    const changeEvent = new Event("change", { bubbles: true });
    textarea.dispatchEvent(changeEvent);
    
    // Remove this overlay and all overlays
    document.querySelectorAll('.pii-textarea-overlay').forEach(el => {
        if (el._updatePosition) {
            window.removeEventListener('scroll', el._updatePosition, true);
            window.removeEventListener('resize', el._updatePosition);
        }
        el.remove();
    });
    
    // Get the actual redaction position (may have been adjusted)
    const actualStart = parseInt(overlayElement.getAttribute('data-pii-start'));
    const actualEnd = parseInt(overlayElement.getAttribute('data-pii-end'));
    
    // Remove this PII from the list
    window.chatGPTFoundPII = window.chatGPTFoundPII.filter(p => 
        !(p.start === start && p.end === end && p.value === piiValue)
    );
    
    // Recalculate offsets for all remaining PII entities based on new text
    // After redaction, offsets shift by the difference between original and redacted length
    const redactionLengthDiff = redactionLabel.length - (actualEnd - actualStart);
    const redactionPoint = newText.indexOf(redactionLabel);
    
    const updatedPII = [];
    window.chatGPTFoundPII.forEach(pii => {
        let newStart = pii.start;
        let newEnd = pii.end;
        
        // If this PII comes after the redaction point, adjust its offsets
        if (pii.start >= actualEnd) {
            newStart = pii.start + redactionLengthDiff;
            newEnd = pii.end + redactionLengthDiff;
        } else if (pii.end > actualStart && pii.start < actualEnd) {
            // This PII overlaps with the redacted one - skip it (shouldn't happen, but safety check)
            console.warn(`[PII Extension] Skipping overlapping PII: ${pii.value}`);
            return;
        }
        
        // Verify the PII still exists at the new position
        const textAtNewPosition = newText.substring(newStart, newEnd);
        if (textAtNewPosition === pii.value || textAtNewPosition.toLowerCase() === pii.value.toLowerCase()) {
            updatedPII.push({
                ...pii,
                start: newStart,
                end: newEnd
            });
        } else {
            // Try to find it by value
            const lowerNewText = newText.toLowerCase();
            const lowerPiiValue = pii.value.toLowerCase();
            const foundIndex = lowerNewText.indexOf(lowerPiiValue, Math.max(0, newStart - 10));
            
            if (foundIndex !== -1) {
                updatedPII.push({
                    ...pii,
                    start: foundIndex,
                    end: foundIndex + pii.value.length
                });
                console.log(`[PII Extension] Recalculated PII "${pii.value}" to position ${foundIndex}`);
            } else {
                console.warn(`[PII Extension] Could not find remaining PII "${pii.value}" after redaction`);
            }
        }
    });
    
    window.chatGPTFoundPII = updatedPII;
    
    // Recreate highlights for remaining PII with updated offsets
    if (window.chatGPTFoundPII.length > 0) {
        createInlineHighlightsForTextarea(textarea, window.chatGPTFoundPII, newText);
    }
    
    popup.remove();
    console.log(`[PII Extension] Accepted and redacted: ${piiType} "${piiValue}" -> "${redactionLabel}"`);
}

// Reject individual PII suggestion in textarea
function rejectTextareaSuggestion(overlayElement, suggestionId, popup) {
    const piiValue = overlayElement.getAttribute('data-pii-value');
    const piiType = overlayElement.getAttribute('data-pii-type');
    const start = parseInt(overlayElement.getAttribute('data-pii-start'));
    const end = parseInt(overlayElement.getAttribute('data-pii-end'));
    
    // Remove this overlay
    if (overlayElement._updatePosition) {
        window.removeEventListener('scroll', overlayElement._updatePosition, true);
    }
    overlayElement.remove();
    
    // Remove this PII from the list
    window.chatGPTFoundPII = window.chatGPTFoundPII.filter(p => 
        !(p.start === start && p.end === end && p.value === piiValue)
    );
    
    popup.remove();
    console.log(`[PII Extension] Rejected: ${piiType} "${piiValue}"`);
}

// ChatGPT/Gemini-specific accept all function
// Uses the new offset tracking system for accurate redaction
function acceptAllPIIForChatGPT() {
    try {
        const pageType = detectPageType();
        const isGemini = pageType === 'gemini';
        
        // Use stored textarea reference if available, otherwise try to find it
        let textarea = window.chatGPTTextarea;
        if (!textarea) {
            const textareaSelectors = [
                'textarea[aria-label*="prompt"]',
                'textarea[aria-label*="message"]',
                'textarea[placeholder*="prompt"]',
                'textarea[placeholder*="message"]',
                'textarea[contenteditable="true"]',
                'div[contenteditable="true"][role="textbox"]',
                'textarea'
            ];
            
            for (const selector of textareaSelectors) {
                textarea = document.querySelector(selector);
                if (textarea) break;
            }
        }
        
        if (!textarea || !window.chatGPTOriginalText || !window.chatGPTFoundPII) {
            console.warn(`[PII Extension] ${isGemini ? 'Gemini' : 'ChatGPT'} data not available for redaction`);
            alert("Please scan for PII first.");
            return;
        }
        
        // Get current text from textarea (may have been modified)
        const currentText = textarea.value || textarea.textContent || window.chatGPTOriginalText || '';
        
        // Find actual positions of PII in current text (similar to highlighting logic)
        // This ensures we redact the correct text even if it has been modified
        const spans = [];
        const lowerText = currentText.toLowerCase();
        
        window.chatGPTFoundPII.forEach(pii => {
            const piiValue = pii.value;
            const lowerPiiValue = piiValue.toLowerCase();
            
            // Find all occurrences of this PII in the current text
            let searchIndex = 0;
            while (true) {
                const foundIndex = lowerText.indexOf(lowerPiiValue, searchIndex);
                if (foundIndex === -1) break;
                
                // Get the actual text at this position
                const actualText = currentText.substring(foundIndex, foundIndex + piiValue.length);
                
                // Verify it matches and is not already redacted
                if (actualText.toLowerCase() === lowerPiiValue && 
                    !isRedactedText(currentText, foundIndex, foundIndex + piiValue.length)) {
                    spans.push({
                        start: foundIndex,
                        end: foundIndex + piiValue.length,
                        entity: {
                            type: pii.type,
                            value: actualText
                        }
                    });
                }
                
                searchIndex = foundIndex + 1;
            }
        });
        
        if (spans.length === 0) {
            alert("No PII found to redact. The text may have been modified or already redacted.");
            return;
        }
        
        // Sort spans by start position (required for offset tracking)
        spans.sort((a, b) => a.start - b.start);
        
        // Create mask function
        const maskFor = (entity) => {
            return getRedactionLabel(entity.type);
        };
        
        // Use the new offset tracking system to redact all PII
        // This ensures offsets are correctly maintained after each redaction
        const result = redactPIIWithOffsetTracking(currentText, spans, maskFor);
        
        console.log(`[PII Extension] Redacted ${spans.length} PII items using offset tracking system`);
        console.log(`[PII Extension] Original text length: ${currentText.length}, Redacted length: ${result.text.length}`);
        
        // Update input field safely (works for both ChatGPT and Gemini)
        const success = setChatGPTInputValue(result.text, textarea);
        if (success) {
            // Remove all overlays
            document.querySelectorAll('.pii-textarea-overlay').forEach(el => {
                if (el._updatePosition) {
                    window.removeEventListener('scroll', el._updatePosition, true);
                    window.removeEventListener('resize', el._updatePosition);
                }
                el.remove();
            });
            
            alert(`Successfully redacted ${spans.length} PII items. Your message is ready to send.`);
            
            // Clean up stored data
            delete window.chatGPTOriginalText;
            delete window.chatGPTFoundPII;
            delete window.chatGPTTextarea;
        } else {
            alert(`Failed to update ${isGemini ? 'Gemini' : 'ChatGPT'} input. Please try again.`);
        }
        
    } catch (error) {
        console.error("[PII Extension] Error in chat interface accept all:", error);
        alert("Error redacting PII. Please try again.");
    }
}

// Helper function to get all text nodes within an element
function getTextNodesIn(element) {
    const textNodes = [];
    const walker = document.createTreeWalker(
        element,
        NodeFilter.SHOW_TEXT,
        {
            acceptNode: function(node) {
                // Skip empty text nodes and script/style content
                if (node.textContent.trim().length === 0) {
                    return NodeFilter.FILTER_REJECT;
                }
                // Skip nodes in script, style, or other non-content elements
                const parent = node.parentElement;
                if (parent && (parent.tagName === 'SCRIPT' || parent.tagName === 'STYLE' || parent.tagName === 'NOSCRIPT')) {
                    return NodeFilter.FILTER_REJECT;
                }
                return NodeFilter.FILTER_ACCEPT;
            }
        }
    );
    
    let node;
    while (node = walker.nextNode()) {
        textNodes.push(node);
        // Debug: log first few characters of each text node
        if (textNodes.length <= 5) {
            console.log(`Text node ${textNodes.length}: "${node.textContent.substring(0, 50)}..."`);
        }
    }
    
    // If we found some text nodes, log a sample of the content
    if (textNodes.length > 0) {
        const sampleText = textNodes.slice(0, 3).map(n => n.textContent.trim()).join(' ');
        console.log(`Sample content from text nodes: "${sampleText.substring(0, 100)}..."`);
    }
    
    return textNodes;
}

// Check if a node is already highlighted
function isAlreadyHighlighted(node) {
    let parent = node.parentElement;
    while (parent) {
        if (parent.classList && parent.classList.contains(HIGHLIGHT_CLASS)) {
            return true;
        }
        parent = parent.parentElement;
    }
    return false;
}

// Highlight specific text within a text node
function highlightTextInNode(textNode, startIndex, length, entity) {
    try {
        const text = textNode.textContent;
        const beforeText = text.substring(0, startIndex);
        const highlightedText = text.substring(startIndex, startIndex + length);
        const afterText = text.substring(startIndex + length);

        // Create highlight span
        const highlightSpan = document.createElement('span');
        highlightSpan.className = HIGHLIGHT_CLASS;
        highlightSpan.setAttribute('data-pii-type', entity.type);
        highlightSpan.setAttribute('data-pii-value', entity.value);
        highlightSpan.textContent = highlightedText;
        highlightSpan.style.backgroundColor = '#FBBF24';
        highlightSpan.style.color = '#000';
        highlightSpan.style.cursor = 'pointer';
        highlightSpan.style.padding = '2px';
        highlightSpan.style.borderRadius = '3px';

        // Create document fragment to replace the text node
        const fragment = document.createDocumentFragment();
        
        if (beforeText) {
            fragment.appendChild(document.createTextNode(beforeText));
        }
        
        fragment.appendChild(highlightSpan);
        
        if (afterText) {
            fragment.appendChild(document.createTextNode(afterText));
        }

        // Replace the original text node with the fragment
        textNode.parentNode.replaceChild(fragment, textNode);
        
        console.log(`Highlighted: "${highlightedText}" as ${entity.type}`);
    } catch (error) {
        console.error('Error highlighting text:', error);
    }
}

// Adds click listeners to the highlighted PII spans for suggestions
function addRedactEvents() {
    document.querySelectorAll(`.${HIGHLIGHT_CLASS}`).forEach(el => {
        // Skip if already processed or rejected
        if (el.classList.contains(REJECTED_CLASS)) return;
        
        el.onclick = (event) => {
            event.stopPropagation(); // Prevents interference with page editor
            showSuggestionPopup(el);
        };
        
        // Add hover effect
        el.style.cursor = 'pointer';
        el.title = 'Click to review PII suggestion';
    });
}

// Overlay highlighting system for protected content areas
function highlightWithOverlay(entities) {
    console.log("Starting overlay highlighting system...");
    
    // Remove any existing overlays
    document.querySelectorAll('.pii-overlay-highlight').forEach(el => el.remove());
    
    let highlightCount = 0;
    
    // Sort entities by length (longest first)
    const sortedEntities = entities.sort((a, b) => b.value.length - a.value.length);
    
    sortedEntities.forEach(entity => {
        console.log(`Looking for "${entity.value}" to overlay highlight...`);
        
        // Find all text nodes in the document
        const walker = document.createTreeWalker(
            document.body,
            NodeFilter.SHOW_TEXT,
            null,
            false
        );
        
        let node;
        while (node = walker.nextNode()) {
            const text = node.textContent;
            const lowerText = text.toLowerCase();
            const lowerEntity = entity.value.toLowerCase();
            
            let index = lowerText.indexOf(lowerEntity);
            
            // Try normalized search if exact fails
            if (index === -1) {
                const normalizedText = lowerText.normalize("NFD").replace(/[\u0300-\u036f]/g, "");
                const normalizedEntity = lowerEntity.normalize("NFD").replace(/[\u0300-\u036f]/g, "");
                index = normalizedText.indexOf(normalizedEntity);
            }
            
            if (index !== -1) {
                const parent = node.parentElement;
                if (parent && isElementVisible(parent)) {
                    const rect = getTextPosition(parent, text, index, entity.value.length);
                    if (rect) {
                        createOverlayHighlight(rect, entity);
                        highlightCount++;
                        console.log(`✅ Created overlay for "${entity.value}"`);
                        break; // Only highlight first occurrence
                    }
                }
            }
        }
    });
    
    if (highlightCount > 0) {
        console.log(`Successfully created ${highlightCount} overlay highlights`);
        alert(`Overlay highlighting complete! Found ${highlightCount} PII suggestions. Click yellow boxes to review and accept/reject.`);
    } else {
        alert("Could not create overlay highlights. The text might not be accessible for positioning.");
    }
}

// Check if an element is visible on screen
function isElementVisible(element) {
    const rect = element.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0 && 
           rect.top >= 0 && rect.left >= 0 && 
           rect.bottom <= window.innerHeight && 
           rect.right <= window.innerWidth;
}

// Get position of text within an element
function getTextPosition(element, fullText, startIndex, length) {
    try {
        const rect = element.getBoundingClientRect();
        
        // Simple approximation - use element's position
        // This is a fallback when Range API doesn't work
        return {
            left: rect.left + window.scrollX,
            top: rect.top + window.scrollY,
            width: Math.max(100, length * 8), // Approximate width
            height: rect.height || 20
        };
    } catch (error) {
        console.error('Error getting text position:', error);
        return null;
    }
}

// Create an overlay highlight element with suggestion support
function createOverlayHighlight(rect, entity) {
    const overlay = document.createElement('div');
    overlay.className = 'pii-overlay-highlight';
    overlay.setAttribute('data-pii-type', entity.type);
    overlay.setAttribute('data-pii-value', entity.value);
    overlay.setAttribute('data-suggestion-id', generateSuggestionId());
    
    overlay.style.position = 'absolute';
    overlay.style.left = rect.left + 'px';
    overlay.style.top = rect.top + 'px';
    overlay.style.width = rect.width + 'px';
    overlay.style.height = rect.height + 'px';
    overlay.style.backgroundColor = 'rgba(251, 191, 36, 0.7)'; // New palette yellow with transparency
    overlay.style.border = '2px solid #F59E0B';
    overlay.style.borderRadius = '3px';
    overlay.style.pointerEvents = 'auto';
    overlay.style.cursor = 'pointer';
    overlay.style.zIndex = '999999';
    overlay.style.boxSizing = 'border-box';
    
    // Add click handler for suggestions
    overlay.onclick = (event) => {
        event.stopPropagation();
        showOverlaySuggestionPopup(overlay);
    };
    
    // Add tooltip
    overlay.title = `Click to review ${entity.type}: ${entity.value}`;
    
    document.body.appendChild(overlay);
}

// Show suggestion popup for overlay highlights
function showOverlaySuggestionPopup(overlayElement) {
    // Remove any existing popups
    document.querySelectorAll(`.${SUGGESTION_POPUP_CLASS}`).forEach(popup => popup.remove());
    
    const piiValue = overlayElement.getAttribute('data-pii-value');
    const piiType = overlayElement.getAttribute('data-pii-type');
    const suggestionId = overlayElement.getAttribute('data-suggestion-id');
    
    // Create popup similar to regular suggestion popup
    const popup = document.createElement('div');
    popup.className = SUGGESTION_POPUP_CLASS;
    
    // Position popup near the overlay
    const rect = overlayElement.getBoundingClientRect();
    popup.style.left = Math.min(rect.left, window.innerWidth - 440) + 'px';
    popup.style.top = (rect.bottom + 10) + 'px';
    
    // Create popup content
    popup.innerHTML = `
        <div style="margin-bottom: 12px;">
            <strong>PII Detected (Overlay Mode)</strong>
        </div>
        <div style="margin-bottom: 8px;">
            <strong>Type:</strong> ${piiType}
        </div>
        <div style="margin-bottom: 8px;">
            <strong>Value:</strong> "<span class="pii-value-highlight">${piiValue}</span>"
        </div>
        <div style="margin-bottom: 16px;">
            <strong>Will become:</strong> "<span class="pii-redaction-preview">${getRedactionLabel(piiType)}</span>"
        </div>
        <div style="display: flex; gap: 10px; justify-content: flex-end;">
            <button id="reject-overlay-btn">✕ Reject</button>
            <button id="accept-overlay-btn">✓ Accept</button>
        </div>
    `;
    
    document.body.appendChild(popup);
    
    // Add event listeners
    popup.querySelector('#accept-overlay-btn').onclick = () => acceptOverlaySuggestion(overlayElement, suggestionId, popup);
    popup.querySelector('#reject-overlay-btn').onclick = () => rejectOverlaySuggestion(overlayElement, suggestionId, popup);
    
    // Close popup when clicking outside
    const closePopup = (event) => {
        if (!popup.contains(event.target) && !overlayElement.contains(event.target)) {
            popup.remove();
            document.removeEventListener('click', closePopup);
        }
    };
    
    setTimeout(() => {
        document.addEventListener('click', closePopup);
    }, 100);
}

// Accept overlay PII suggestion
function acceptOverlaySuggestion(overlayElement, suggestionId, popup) {
    const piiValue = overlayElement.getAttribute('data-pii-value');
    const piiType = overlayElement.getAttribute('data-pii-type');
    const pageType = detectPageType();
    
    // Store decision
    suggestionStates.set(suggestionId, 'accepted');
    
    // Change overlay to show it's redacted
    const redactionLabel = getRedactionLabel(piiType);
    overlayElement.style.backgroundColor = 'rgba(34, 211, 238, 0.9)'; // New palette cyan
    overlayElement.style.border = '2px solid #22D3EE';
    overlayElement.innerHTML = `<span style="color: black; font-weight: bold; font-size: 12px; padding: 2px; display: flex; align-items: center; justify-content: center; height: 100%;">${redactionLabel}</span>`;
    overlayElement.onclick = null; // Remove click handler
    overlayElement.style.cursor = 'default';
    overlayElement.title = `Redacted ${piiType}: ${piiValue}`;
    
    // If on ChatGPT, update the input field with sanitized content
    if (pageType === 'chatgpt') {
        setTimeout(() => {
            const sanitizedText = extractSanitizedText();
            if (sanitizedText) {
                setChatGPTInputValue(sanitizedText);
            }
        }, 100); // Small delay to ensure DOM is updated
    }
    
    // Remove popup
    popup.remove();
    
    console.log(`Accepted overlay suggestion: ${piiType} "${piiValue}" -> "${redactionLabel}"`);
}

// Reject overlay PII suggestion
function rejectOverlaySuggestion(overlayElement, suggestionId, popup) {
    const piiValue = overlayElement.getAttribute('data-pii-value');
    const piiType = overlayElement.getAttribute('data-pii-type');
    
    // Store decision
    suggestionStates.set(suggestionId, 'rejected');
    
    // Remove the overlay entirely
    overlayElement.remove();
    
    // Remove popup
    popup.remove();
    
    console.log(`Rejected overlay suggestion: ${piiType} "${piiValue}"`);
}

// Legacy redact function (keeping for backward compatibility)
function showSuggestionPopup(highlightElement) {
    // Remove any existing popups
    document.querySelectorAll(`.${SUGGESTION_POPUP_CLASS}`).forEach(popup => popup.remove());
    
    const piiValue = highlightElement.getAttribute('data-pii-value');
    const piiType = highlightElement.getAttribute('data-pii-type');
    const suggestionId = highlightElement.getAttribute('data-suggestion-id');
    
    // Create popup container
    const popup = document.createElement('div');
    popup.className = SUGGESTION_POPUP_CLASS;
    
    // Position popup near the highlighted element
    const rect = highlightElement.getBoundingClientRect();
    popup.style.left = Math.min(rect.left, window.innerWidth - 440) + 'px';
    popup.style.top = (rect.bottom + 10) + 'px';
    
    // Create popup content
    popup.innerHTML = `
        <div style="margin-bottom: 12px;">
            <strong>PII Detected</strong>
        </div>
        <div style="margin-bottom: 8px;">
            <strong>Type:</strong> ${piiType}
        </div>
        <div style="margin-bottom: 8px;">
            <strong>Value:</strong> "<span class="pii-value-highlight">${piiValue}</span>"
        </div>
        <div style="margin-bottom: 16px;">
            <strong>Will become:</strong> "<span class="pii-redaction-preview">${getRedactionLabel(piiType)}</span>"
        </div>
        <div style="display: flex; gap: 10px; justify-content: flex-end;">
            <button id="reject-btn">✕ Reject</button>
            <button id="accept-btn">✓ Accept</button>
        </div>
    `;
    
    document.body.appendChild(popup);
    
    // Add event listeners
    popup.querySelector('#accept-btn').onclick = () => acceptSuggestion(highlightElement, suggestionId, popup);
    popup.querySelector('#reject-btn').onclick = () => rejectSuggestion(highlightElement, suggestionId, popup);
    
    // Close popup when clicking outside
    const closePopup = (event) => {
        if (!popup.contains(event.target) && !highlightElement.contains(event.target)) {
            popup.remove();
            document.removeEventListener('click', closePopup);
        }
    };
    
    // Add slight delay to prevent immediate closure
    setTimeout(() => {
        document.addEventListener('click', closePopup);
    }, 100);
}

// Accept PII suggestion and redact
function acceptSuggestion(highlightElement, suggestionId, popup) {
    try {
        const piiValue = highlightElement.getAttribute('data-pii-value');
        const piiType = highlightElement.getAttribute('data-pii-type');
        const pageType = detectPageType();
        
        // Store decision
        suggestionStates.set(suggestionId, 'accepted');
        
        // Replace with redaction label
        const redactionLabel = getRedactionLabel(piiType);
        const redactedSpan = document.createElement('span');
        redactedSpan.textContent = redactionLabel;
        redactedSpan.style.cssText = `
            background-color: #22D3EE;
            color: black;
            padding: 2px 6px;
            border-radius: 3px;
            font-weight: bold;
            font-size: 12px;
        `;
        redactedSpan.setAttribute('data-original-value', piiValue);
        redactedSpan.setAttribute('data-pii-type', piiType);
        redactedSpan.classList.add('pii-redacted');
        
        // IMPORTANT: Only replace if parent exists and is safe to modify
        if (highlightElement.parentNode && highlightElement.parentNode.nodeType === Node.ELEMENT_NODE) {
            highlightElement.parentNode.replaceChild(redactedSpan, highlightElement);
        } else {
            console.warn("[PII Extension] Cannot safely replace highlight element");
        }
        
        // If on ChatGPT, update the input field with sanitized content
        if (pageType === 'chatgpt') {
            setTimeout(() => {
                try {
                    const sanitizedText = extractSanitizedText();
                    if (sanitizedText) {
                        setChatGPTInputValue(sanitizedText);
                    }
                } catch (updateError) {
                    console.error("[PII Extension] Error updating ChatGPT input after individual acceptance:", updateError);
                }
            }, 100); // Small delay to ensure DOM is updated
        }
        
        // Remove popup safely
        try {
            if (popup && popup.parentNode) {
                popup.remove();
            }
        } catch (popupError) {
            console.error("[PII Extension] Error removing popup:", popupError);
        }
        
        console.log(`[PII Extension] Accepted suggestion: ${piiType} "${piiValue}" -> "${redactionLabel}"`);
    } catch (error) {
        console.error("[PII Extension] Error in acceptSuggestion:", error);
        
        // Try to remove popup even if other operations failed
        try {
            if (popup && popup.parentNode) {
                popup.remove();
            }
        } catch (popupError) {
            console.error("[PII Extension] Error removing popup after error:", popupError);
        }
    }
}

// Reject PII suggestion and keep original
function rejectSuggestion(highlightElement, suggestionId, popup) {
    const piiValue = highlightElement.getAttribute('data-pii-value');
    const piiType = highlightElement.getAttribute('data-pii-type');
    
    // Store decision
    suggestionStates.set(suggestionId, 'rejected');
    
    // Remove highlighting but keep original text
    const textNode = document.createTextNode(highlightElement.textContent);
    highlightElement.parentNode.replaceChild(textNode, highlightElement);
    
    // Remove popup
    popup.remove();
    
    console.log(`Rejected suggestion: ${piiType} "${piiValue}"`);
}

// Redact function
function handleRedactClick(el) {
    const piiValue = el.getAttribute('data-pii-value');
    const piiType = el.getAttribute('data-pii-type');
    
    if (!piiValue) return;

    // 1. Create masked text
    const mask = '*'.repeat(piiValue.length);
    
    // 2. Replace the highlighted span with masked text
    const maskedTextNode = document.createTextNode(mask);
    el.parentNode.replaceChild(maskedTextNode, el);
    
    console.log(`Redacted: ${piiType} - "${piiValue}" -> "${mask}"`);
    
    // Optional: Show confirmation
    // alert(`Redacted ${piiType}: ${piiValue}`);
}

// Detect page type and adjust behavior accordingly
function detectPageType() {
  const url = window.location.href;
  const hostname = window.location.hostname;
  
  if (hostname.includes('docs.google.com')) {
    return 'google-docs';
  } else if (hostname.includes('chat.openai.com') || hostname.includes('chatgpt.com')) {
    return 'chatgpt';
  } else if (hostname.includes('gemini.google.com') || hostname.includes('bard.google.com')) {
    return 'gemini';
  } else if (hostname.includes('gmail.com')) {
    return 'gmail';
  } else {
    return 'general-web';
  }
}

// Initialize the PII detector with robust DOM loading handling
function initializePiiDetector() {
  const pageType = detectPageType();
  console.log(`Detected page type: ${pageType}`);
  
  // Ensure document.body is available
  if (document.body) {
    injectScanButton();
  } else {
    // Wait for body to be available
    const observer = new MutationObserver((mutations, obs) => {
      if (document.body) {
        injectScanButton();
        obs.disconnect();
      }
    });
    observer.observe(document.documentElement, { childList: true, subtree: true });
  }
}

// Wait for the page to load and then initialize
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initializePiiDetector);
} else {
  // Document is already loaded
  initializePiiDetector();
}

// Fallback: also try after a delay to handle dynamic Google Docs loading
setTimeout(initializePiiDetector, 2000); 

