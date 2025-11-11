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
    
    // Fill (faker) button - generates synthetic PII for redacted places
    const fillButton = document.createElement("button");
    fillButton.id = "pii-fill-button";
    fillButton.innerHTML = `<span role="img" aria-label="Fill">🪄</span> Fill (faker)`;
    fillButton.onclick = () => {
        try {
            fillRedactions();
        } catch (e) {
            console.error('[PII Extension] Error in Fill button:', e);
        }
    };
    
    // Revert PIIs button - replaces fake data in GPT response with original PII
    const revertButton = document.createElement("button");
    revertButton.id = "pii-revert-button";
    revertButton.innerHTML = `<span role="img" aria-label="Revert">↩️</span> Revert PIIs`;
    revertButton.onclick = () => {
        try {
            revertPIIsInResponse();
        } catch (e) {
            console.error('[PII Extension] Error in Revert button:', e);
        }
    };
    
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
    container.appendChild(fillButton);
    container.appendChild(revertButton);
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

// ============================================================================
// FAKER LIBRARY FOR SYNTHETIC DATA GENERATION
// ============================================================================

// Global memory structure to track: original PII -> masked version -> faked version
// Structure: window.piiMapping = Map<uniqueId, {original, masked, fake, type, position}>
if (!window.piiMapping) {
    window.piiMapping = new Map();
}

// Generate unique ID for each PII mapping
function generatePIIMappingId() {
    return 'pii_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
}

// Simple client-side Faker
function randomChoice(arr) {
    return arr[Math.floor(Math.random() * arr.length)];
}

function generateFakeForType(type) {
    // Normalize
    const t = (type || '').toUpperCase();
    switch (t) {
        case 'PERSON':
        case 'NAME':
            return `${randomChoice(['Alex', 'Jordan', 'Taylor', 'Morgan', 'Casey', 'Riley', 'Sam', 'Jamie', 'Avery', 'Quinn'])} ${randomChoice(['Smith','Johnson','Brown','Garcia','Miller','Davis','Wilson','Moore','Taylor','Anderson'])}`;
        case 'EMAIL':
            const name = randomChoice(['alex', 'jordan', 'taylor', 'morgan', 'casey', 'riley', 'sam', 'jamie', 'avery', 'quinn']);
            return `${name}${Math.floor(Math.random()*90+10)}@example.com`;
        case 'PHONE':
        case 'PHONE_NUMBER':
            return `+1-${Math.floor(100+Math.random()*900)}-${Math.floor(100+Math.random()*900)}-${Math.floor(1000+Math.random()*9000)}`;
        case 'LOCATION':
        case 'ADDRESS':
            return `${Math.floor(100+Math.random()*900)} ${randomChoice(['Oak St','Maple Ave','Pine Rd','Elm St','Cedar Ln','Main St','Park Ave','First St','Second Ave'])}, ${randomChoice(['Springfield','Riverton','Lakewood','Fairview','Greenwood','Riverside','Hillcrest','Brookside'])}`;
        case 'ORGANIZATION':
        case 'COMPANY':
            return `${randomChoice(['Acme','Globex','Initech','Umbrella','Stark','Wayne','Oscorp','Cyberdyne','Tyrell'])} ${randomChoice(['LLC','Inc','Group','Co','Corp','Industries'])}`;
        case 'CREDIT_CARD':
            // Simple 16-digit pattern
            return `${Math.floor(4000+Math.random()*5000)} ${Math.floor(1000+Math.random()*9000)} ${Math.floor(1000+Math.random()*9000)} ${Math.floor(1000+Math.random()*9000)}`;
        case 'SSN':
        case 'US_SSN':
            return `${Math.floor(100+Math.random()*900)}-${Math.floor(10+Math.random()*90)}-${Math.floor(1000+Math.random()*9000)}`;
        case 'IP_ADDRESS':
            return `${Math.floor(1+Math.random()*220)}.${Math.floor(1+Math.random()*220)}.${Math.floor(1+Math.random()*220)}.${Math.floor(1+Math.random()*220)}`;
        case 'URL':
            return `https://www.${randomChoice(['example','demo','sample','testsite','placeholder'])}.com/${Math.random().toString(36).substring(2,8)}`;
        case 'DATE_TIME':
            return `${Math.floor(1+Math.random()*12)}/${Math.floor(1+Math.random()*28)}/20${Math.floor(20+Math.random()*6)}`;
        default:
            // Generic fallback - small random token
            return `${randomChoice(['Pat','Lee','Jo','De','Kim','Max'])}${Math.floor(Math.random()*9000)}`;
    }
}

// Map redaction labels to types
function labelToType(label) {
    if (!label) return null;
    const l = label.replace(/\[|\]/g, '').toUpperCase();
    switch (l) {
        case 'NAME': return 'PERSON';
        case 'EMAIL': return 'EMAIL';
        case 'PHONE': return 'PHONE';
        case 'LOCATION': return 'LOCATION';
        case 'ORGANIZATION': return 'ORGANIZATION';
        case 'REDACTED': return 'PERSON';
        case 'ID': return 'ID';
        case 'BANK_ACCOUNT': return 'BANK_ACCOUNT';
        case 'SSN': return 'SSN';
        case 'URL': return 'URL';
        case 'DATE_TIME': return 'DATE_TIME';
        default: return l;
    }
}

// ============================================================================
// END FAKER LIBRARY
// ============================================================================

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

/**
 * Enhanced textarea finder for ChatGPT/Gemini
 * Tries multiple selectors and methods to find the input field
 * Returns { textarea, selector, text } or null if not found
 */
function findChatGPTTextarea() {
    const pageType = detectPageType();
    if (pageType !== 'chatgpt' && pageType !== 'gemini') {
        return null;
    }
    
    const isGemini = pageType === 'gemini';
    
    // Enhanced selectors for ChatGPT/Gemini - try more specific ones first
    const textareaSelectors = [
        // ChatGPT specific selectors
        'textarea#prompt-textarea',
        'textarea[data-id="root"]',
        'textarea[tabindex="0"]',
        'div[contenteditable="true"][data-id="root"]',
        'div[contenteditable="true"][tabindex="0"]',
        'textarea[aria-label*="prompt"]',
        'textarea[aria-label*="Message"]',
        'textarea[aria-label*="message"]',
        'textarea[placeholder*="prompt"]',
        'textarea[placeholder*="Message"]',
        'textarea[placeholder*="message"]',
        'textarea[contenteditable="true"]',
        'div[contenteditable="true"][role="textbox"]',
        'div[contenteditable="true"]',
        // More generic selectors
        'textarea',
        'div[role="textbox"]'
    ];
    
    let textarea = null;
    let foundSelector = null;
    
    for (const selector of textareaSelectors) {
        try {
            const elements = document.querySelectorAll(selector);
            // Try to find the one that's actually visible and is the input
            for (const el of elements) {
                const rect = el.getBoundingClientRect();
                const isVisible = rect.width > 0 && rect.height > 0;
                const isInput = el.tagName === 'TEXTAREA' || 
                              (el.contentEditable === 'true' && el.getAttribute('role') === 'textbox') ||
                              (el.contentEditable === 'true' && el.hasAttribute('data-id'));
                
                if (isVisible && isInput) {
                    textarea = el;
                    foundSelector = selector;
                    break;
                }
            }
            
            if (textarea) break;
            
            // Fallback: just use the first one if any found
            if (elements.length > 0) {
                textarea = elements[0];
                foundSelector = selector;
                break;
            }
        } catch (e) {
            console.warn(`[PII Extension] Error with selector ${selector}:`, e);
        }
    }
    
    if (!textarea) {
        console.warn(`[PII Extension] ${isGemini ? 'Gemini' : 'ChatGPT'} input field not found`);
        console.warn('[PII Extension] Available textareas on page:', document.querySelectorAll('textarea').length);
        console.warn('[PII Extension] Available contenteditable divs:', document.querySelectorAll('div[contenteditable="true"]').length);
        return null;
    }
    
    // Get text from input field (handle both textarea.value and contenteditable divs)
    let text = textarea.value || textarea.textContent || textarea.innerText || '';
    
    // For contenteditable divs, try to get text from child nodes
    if (!text && textarea.contentEditable === 'true') {
        const walker = document.createTreeWalker(
            textarea,
            NodeFilter.SHOW_TEXT,
            null,
            false
        );
        
        let textNodes = [];
        let node;
        while (node = walker.nextNode()) {
            textNodes.push(node.textContent);
        }
        text = textNodes.join('');
    }
    
    // Also try querySelector for nested divs
    if (!text && textarea.querySelector) {
        const nestedDiv = textarea.querySelector('div');
        if (nestedDiv) {
            text = nestedDiv.textContent || nestedDiv.innerText || '';
        }
    }
    
    return {
        textarea: textarea,
        selector: foundSelector,
        text: text
    };
}

// Safely set ChatGPT/Gemini input value and trigger React state update
function setChatGPTInputValue(newText, textareaElement = null) {
    try {
        // Use provided textarea or try to find it using the enhanced finder
        let textarea = textareaElement;
        if (!textarea) {
            const textareaResult = findChatGPTTextarea();
            if (textareaResult && textareaResult.textarea) {
                textarea = textareaResult.textarea;
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
            
            // Alert removed per user request
            // if (showAlert) {
            //     alert("Highlights cleared.");
            // }
            
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
        
        // Alerts removed per user request
        // if (showAlert && totalCleared > 0) {
        //     alert(`All highlights and redactions cleared. (${textHighlightCount} highlights + ${redactedElements.length} redactions)`);
        // } else if (showAlert && totalCleared === 0) {
        //     alert("No highlights to clear.");
        // }
        
        console.log(`[PII Extension] Cleared ${totalCleared} elements successfully`);
    } catch (error) {
        console.error("[PII Extension] Critical error in clearHighlights:", error);
        // Alert removed per user request
        // if (showAlert) {
        //     alert("An error occurred while clearing highlights. Some elements may remain highlighted.");
        // }
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
        
        // Alerts removed per user request
        // if (acceptedCount > 0) {
        //     alert(`Successfully accepted and redacted ${acceptedCount} PII elements.`);
        // } else {
        //     alert("No PII detected to accept. Please scan for PII first.");
        // }
        
        console.log(`[PII Extension] Accept All completed. ${acceptedCount} PII elements processed.`);
    } catch (error) {
        console.error("[PII Extension] Critical error in acceptAllPII:", error);
        // Alert removed per user request
        // alert("An error occurred while processing PII. Please try again.");
    }
}

// Replace redaction labels in chat input and replace .pii-redacted spans in DOM with fake data
// Stores mapping: original PII -> masked version -> faked version in window.piiMapping
function fillRedactions() {
    const pageType = detectPageType();
    
    // Regex for redaction labels like [NAME], [EMAIL], etc.
    const labelRegex = /\[(NAME|LOCATION|EMAIL|PHONE|ORGANIZATION|REDACTED|ID|BANK_ACCOUNT|SSN|URL|DATE_TIME)\]/gi;
    
    if (pageType === 'chatgpt' || pageType === 'gemini') {
        const textareaResult = findChatGPTTextarea();
        if (!textareaResult || !textareaResult.textarea) {
            console.warn('[PII Extension] Input field not found for filling faker data.');
            return;
        }
        
        const textarea = textareaResult.textarea;
        let text = textarea.value || textarea.textContent || textarea.innerText || '';
        if (!text || text.trim().length === 0) {
            console.warn('[PII Extension] No text found in input to fill.');
            return;
        }
        
        let replacedCount = 0;
        const mappings = []; // Store mappings for this fill operation
        
        // Replace each redaction label with fake data and track the mapping
        let matchIndex = 0;
        const newText = text.replace(labelRegex, (match, labelType) => {
            const piiType = labelToType(match);
            const fake = generateFakeForType(piiType);
            const matchPosition = text.indexOf(match, matchIndex);
            matchIndex = matchPosition + match.length;
            
            // Try to find existing mapping by masked label and type
            let existingMapping = null;
            for (const [id, mapping] of window.piiMapping.entries()) {
                if (mapping.masked === match && mapping.type === piiType && mapping.fake === null) {
                    existingMapping = mapping;
                    break;
                }
            }
            
            if (existingMapping) {
                // Update existing mapping with fake value
                existingMapping.fake = fake;
                existingMapping.filledTimestamp = Date.now();
                mappings.push(existingMapping);
                console.log(`[PII Extension] Updated existing mapping: ${existingMapping.original} -> ${existingMapping.masked} -> ${existingMapping.fake}`);
            } else {
                // Create new mapping if not found
                const mappingId = generatePIIMappingId();
                // Try to find original PII value from stored data
                let originalValue = match; // Default to masked label if original not found
                
                // Try to match by position in original text if available
                if (window.chatGPTOriginalText && window.chatGPTFoundPII) {
                    // This is approximate - we'll use the masked label as fallback
                    originalValue = match;
                }
                
                const mapping = {
                    id: mappingId,
                    original: originalValue,
                    masked: match,
                    fake: fake,
                    type: piiType,
                    position: matchPosition,
                    timestamp: Date.now(),
                    filledTimestamp: Date.now()
                };
                
                mappings.push(mapping);
                window.piiMapping.set(mappingId, mapping);
                console.log(`[PII Extension] Created new mapping: ${mapping.original} -> ${mapping.masked} -> ${mapping.fake}`);
            }
            
            replacedCount++;
            return fake;
        });
        
        if (replacedCount === 0) {
            console.log('[PII Extension] No redaction labels found to fill.');
            return;
        }
        
        const success = setChatGPTInputValue(newText, textarea);
        if (success) {
            // Remove overlays and popups
            document.querySelectorAll('.pii-textarea-overlay, .pii-suggestion-popup').forEach(el => {
                if (el._updatePosition) {
                    window.removeEventListener('scroll', el._updatePosition, true);
                    window.removeEventListener('resize', el._updatePosition);
                }
                el.remove();
            });
            
            console.log(`[PII Extension] Filled ${replacedCount} redactions with synthetic data. Mappings stored in window.piiMapping`);
        } else {
            console.error('[PII Extension] Failed to update input field with fake data.');
        }
        
        return;
    }
    
    // For general pages: replace .pii-redacted spans
    const redactedSpans = Array.from(document.querySelectorAll('.pii-redacted'));
    if (redactedSpans.length === 0) {
        console.log('[PII Extension] No redacted spans found on this page to fill.');
        return;
    }
    
    let filled = 0;
    redactedSpans.forEach(span => {
        try {
            const originalValue = span.getAttribute('data-original-value') || span.textContent || '';
            const piiType = span.getAttribute('data-pii-type') || labelToType(span.textContent) || 'PERSON';
            const maskedLabel = span.textContent || '';
            const fake = generateFakeForType(piiType);
            
            // Create mapping
            const mappingId = generatePIIMappingId();
            const mapping = {
                id: mappingId,
                original: originalValue,
                masked: maskedLabel,
                fake: fake,
                type: piiType,
                position: -1, // DOM position, not text position
                timestamp: Date.now()
            };
            
            window.piiMapping.set(mappingId, mapping);
            
            // Replace span with fake data
            const textNode = document.createTextNode(fake);
            // Preserve original in data attribute if not already present
            if (!span.hasAttribute('data-original-value')) {
                span.setAttribute('data-original-value', originalValue);
            }
            span.setAttribute('data-fake-value', fake);
            span.setAttribute('data-mapping-id', mappingId);
            
            // Replace the text content but keep the span for styling
            span.textContent = fake;
            span.classList.remove('pii-redacted');
            span.classList.add('pii-filled');
            
            filled++;
            console.log(`[PII Extension] Mapping stored: ${mapping.original} -> ${mapping.masked} -> ${mapping.fake}`);
        } catch (e) {
            console.error('[PII Extension] Error filling a redacted span:', e);
        }
    });
    
    console.log(`[PII Extension] Filled ${filled} redacted spans with synthetic data. Mappings stored in window.piiMapping`);
}

// Revert fake PII data in ChatGPT/Gemini response back to original PII values
function revertPIIsInResponse() {
    const pageType = detectPageType();
    
    if (pageType !== 'chatgpt' && pageType !== 'gemini') {
        console.warn('[PII Extension] Revert PIIs only works on ChatGPT/Gemini pages');
        return;
    }
    
    // Check if we have mappings
    if (!window.piiMapping || window.piiMapping.size === 0) {
        console.warn('[PII Extension] No PII mappings found. Please scan, accept, and fill PIIs first.');
        return;
    }
    
    // Get mappings that have fake data (were filled)
    const filledMappings = [];
    for (const [id, mapping] of window.piiMapping.entries()) {
        if (mapping.fake && mapping.original) {
            filledMappings.push(mapping);
        }
    }
    
    if (filledMappings.length === 0) {
        console.warn('[PII Extension] No filled mappings found. Please fill PIIs first.');
        return;
    }
    
    console.log(`[PII Extension] Found ${filledMappings.length} filled mappings to revert`);
    
    // Find ChatGPT/Gemini response messages
    // ChatGPT typically uses: div[data-message-author-role="assistant"]
    // Also try other common selectors
    const responseSelectors = [
        'div[data-message-author-role="assistant"]',
        'div[data-testid*="conversation-turn"]',
        'div.markdown',
        'div.prose',
        'div[class*="message"]',
        'div[class*="response"]',
        'div[class*="assistant"]'
    ];
    
    let responseElements = [];
    for (const selector of responseSelectors) {
        try {
            const elements = document.querySelectorAll(selector);
            if (elements.length > 0) {
                responseElements = Array.from(elements);
                console.log(`[PII Extension] Found ${elements.length} potential response elements with selector: ${selector}`);
                break;
            }
        } catch (e) {
            console.warn(`[PII Extension] Error with selector ${selector}:`, e);
        }
    }
    
    // If no specific selector worked, try to find the latest message in the conversation
    if (responseElements.length === 0) {
        // Try to find conversation container and get latest message
        const conversationContainers = [
            'div[class*="conversation"]',
            'div[class*="chat"]',
            'main',
            'div[role="main"]'
        ];
        
        for (const containerSelector of conversationContainers) {
            try {
                const container = document.querySelector(containerSelector);
                if (container) {
                    // Get all text nodes or divs that might contain the response
                    const allDivs = container.querySelectorAll('div');
                    if (allDivs.length > 0) {
                        // Get the last few divs (likely the latest response)
                        responseElements = Array.from(allDivs).slice(-5);
                        console.log(`[PII Extension] Using fallback: found ${responseElements.length} elements from container`);
                        break;
                    }
                }
            } catch (e) {
                console.warn(`[PII Extension] Error with container selector ${containerSelector}:`, e);
            }
        }
    }
    
    if (responseElements.length === 0) {
        console.warn('[PII Extension] Could not find ChatGPT response elements. Trying to find by text content...');
        
        // Last resort: search entire document for fake values
        let revertedCount = 0;
        let totalReplacements = 0;
        
        // Sort mappings by fake value length (longest first) to avoid partial replacements
        const sortedMappings = filledMappings.sort((a, b) => b.fake.length - a.fake.length);
        
        // Process each mapping
        for (const mapping of sortedMappings) {
            const fakeValue = mapping.fake;
            const originalValue = mapping.original;
            
            // Escape special regex characters
            const escapedFake = fakeValue.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
            
            // Create multiple regex patterns for better matching
            const regexPatterns = [];
            
            if (mapping.type === 'PERSON' || mapping.type === 'NAME') {
                // For names, try multiple patterns:
                // 1. Full name with word boundaries
                regexPatterns.push(new RegExp(`\\b${escapedFake}\\b`, 'gi'));
                
                // 2. Split name into first and last (GPT might use just first or last name)
                const nameParts = fakeValue.split(/\s+/);
                if (nameParts.length >= 2) {
                    const firstName = nameParts[0];
                    const lastName = nameParts[nameParts.length - 1];
                    const originalParts = originalValue.split(/\s+/);
                    
                    // Match first name only if original also has it
                    if (originalParts.length >= 1) {
                        regexPatterns.push(new RegExp(`\\b${firstName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, 'gi'));
                    }
                    // Match last name only if original also has it
                    if (originalParts.length >= 2) {
                        regexPatterns.push(new RegExp(`\\b${lastName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, 'gi'));
                    }
                }
            } else if (mapping.type === 'LOCATION') {
                // For locations, ONLY match the full location string
                // Do NOT do partial matching - locations are too complex and GPT reformats them significantly
                // Partial matching causes incorrect replacements (e.g., "Oak Street" -> wrong location)
                regexPatterns.push(new RegExp(escapedFake.replace(/\s+/g, '\\s+'), 'gi'));
            } else {
                // For emails, phones, etc., use exact match with flexible whitespace
                regexPatterns.push(new RegExp(escapedFake.replace(/\s+/g, '\\s+'), 'gi'));
            }
            
            // Try each pattern
            for (const regex of regexPatterns) {
                // Search and replace in all text nodes
                const walker = document.createTreeWalker(
                    document.body,
                    NodeFilter.SHOW_TEXT,
                    null,
                    false
                );
                
                let node;
                const nodesToUpdate = [];
                
                while (node = walker.nextNode()) {
                    if (node.textContent && regex.test(node.textContent)) {
                        nodesToUpdate.push(node);
                    }
                }
                
                // Replace in found nodes
                for (const textNode of nodesToUpdate) {
                    const originalText = textNode.textContent;
                    
                    // Determine replacement value based on what was matched
                    let replacementValue = originalValue;
                    if (mapping.type === 'PERSON' || mapping.type === 'NAME') {
                        // If matching a partial name, replace with corresponding part
                        const nameParts = fakeValue.split(/\s+/);
                        const originalParts = originalValue.split(/\s+/);
                        const matchText = originalText.match(regex)?.[0] || '';
                        
                        if (nameParts.length >= 2 && originalParts.length >= 2) {
                            if (matchText.toLowerCase() === nameParts[0].toLowerCase()) {
                                replacementValue = originalParts[0]; // First name
                            } else if (matchText.toLowerCase() === nameParts[nameParts.length - 1].toLowerCase()) {
                                replacementValue = originalParts[originalParts.length - 1]; // Last name
                            }
                        }
                    }
                    
                    const newText = originalText.replace(regex, (match) => {
                        // Case-sensitive replacement to preserve formatting
                        if (match === fakeValue) {
                            return replacementValue;
                        } else if (match.toLowerCase() === fakeValue.toLowerCase()) {
                            // Preserve case of first letter if different
                            if (match[0] === match[0].toUpperCase() && replacementValue[0]) {
                                return replacementValue[0].toUpperCase() + replacementValue.slice(1);
                            }
                            return replacementValue;
                        } else if (mapping.type === 'PERSON' || mapping.type === 'NAME') {
                            // Partial name match
                            return replacementValue;
                        }
                        return match;
                    });
                    
                    if (newText !== originalText) {
                        textNode.textContent = newText;
                        totalReplacements++;
                    }
                }
                
                if (nodesToUpdate.length > 0) {
                    revertedCount++;
                    console.log(`[PII Extension] Reverted: "${fakeValue}" -> "${originalValue}" (${nodesToUpdate.length} occurrences)`);
                    break; // Found matches, move to next mapping
                }
            }
        }
        
        console.log(`[PII Extension] Revert complete: ${revertedCount} mappings reverted, ${totalReplacements} total replacements`);
        return;
    }
    
    // Process response elements
    let totalReverted = 0;
    let totalReplacements = 0;
    
    // Sort mappings by fake value length (longest first) to avoid partial replacements
    const sortedMappings = filledMappings.sort((a, b) => b.fake.length - a.fake.length);
    
    for (const element of responseElements) {
        let elementText = element.textContent || element.innerText || '';
        if (!elementText.trim()) continue;
        
        let modified = false;
        let modifiedText = elementText;
        
        // Process each mapping
        for (const mapping of sortedMappings) {
            const fakeValue = mapping.fake;
            const originalValue = mapping.original;
            
            // Escape special regex characters
            const escapedFake = fakeValue.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
            
            // Create multiple regex patterns for better matching
            const regexPatterns = [];
            
            if (mapping.type === 'PERSON' || mapping.type === 'NAME') {
                // For names, try multiple patterns
                regexPatterns.push(new RegExp(`\\b${escapedFake}\\b`, 'gi'));
                
                // Split name into parts for partial matching
                const nameParts = fakeValue.split(/\s+/);
                if (nameParts.length >= 2) {
                    const firstName = nameParts[0];
                    const lastName = nameParts[nameParts.length - 1];
                    const originalParts = originalValue.split(/\s+/);
                    
                    if (originalParts.length >= 1) {
                        regexPatterns.push(new RegExp(`\\b${firstName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, 'gi'));
                    }
                    if (originalParts.length >= 2) {
                        regexPatterns.push(new RegExp(`\\b${lastName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, 'gi'));
                    }
                }
            } else if (mapping.type === 'LOCATION') {
                // For locations, ONLY match the full location string with flexible whitespace
                // Do NOT do partial matching - locations are too complex and GPT reformats them
                regexPatterns.push(new RegExp(escapedFake.replace(/\s+/g, '\\s+'), 'gi'));
            } else {
                regexPatterns.push(new RegExp(escapedFake.replace(/\s+/g, '\\s+'), 'gi'));
            }
            
            // Try each pattern
            for (const regex of regexPatterns) {
                const matches = modifiedText.match(regex);
                if (matches && matches.length > 0) {
                    // Determine replacement value
                    let replacementValue = originalValue;
                    if (mapping.type === 'PERSON' || mapping.type === 'NAME') {
                        const nameParts = fakeValue.split(/\s+/);
                        const originalParts = originalValue.split(/\s+/);
                        const firstMatch = matches[0];
                        
                        if (nameParts.length >= 2 && originalParts.length >= 2) {
                            if (firstMatch.toLowerCase() === nameParts[0].toLowerCase()) {
                                replacementValue = originalParts[0];
                            } else if (firstMatch.toLowerCase() === nameParts[nameParts.length - 1].toLowerCase()) {
                                replacementValue = originalParts[originalParts.length - 1];
                            }
                        }
                    }
                    
                    // Replace with original, preserving case if possible
                    modifiedText = modifiedText.replace(regex, (match) => {
                        if (match === fakeValue) {
                            return replacementValue;
                        } else if (match.toLowerCase() === fakeValue.toLowerCase()) {
                            if (match[0] === match[0].toUpperCase() && replacementValue[0]) {
                                return replacementValue[0].toUpperCase() + replacementValue.slice(1);
                            }
                            return replacementValue;
                        } else if (mapping.type === 'PERSON' || mapping.type === 'NAME') {
                            return replacementValue;
                        }
                        return match;
                    });
                    
                    modified = true;
                    totalReplacements += matches.length;
                    console.log(`[PII Extension] Reverted in response: "${fakeValue}" -> "${replacementValue}" (${matches.length} occurrences)`);
                    break; // Found matches, move to next mapping
                }
            }
        }
        
        if (modified) {
            // Preserve DOM structure by replacing only text nodes, not the entire element
            // This maintains GPT's formatting, line breaks, and HTML structure
            const walker = document.createTreeWalker(
                element,
                NodeFilter.SHOW_TEXT,
                null,
                false
            );
            
            let textNode;
            const textNodes = [];
            
            // Collect all text nodes
            while (textNode = walker.nextNode()) {
                textNodes.push(textNode);
            }
            
            // Apply replacements directly to each text node to preserve structure
            // Process each text node individually with all mappings
            for (const textNode of textNodes) {
                let nodeText = textNode.textContent;
                let nodeModified = false;
                
                // Apply each mapping replacement to this text node
                // Process in reverse order (longest first) to avoid partial replacements
                for (const mapping of sortedMappings) {
                    const fakeValue = mapping.fake;
                    const originalValue = mapping.original;
                    const escapedFake = fakeValue.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
                    
                    // Create appropriate regex based on PII type
                    let regex;
                    if (mapping.type === 'PERSON' || mapping.type === 'NAME') {
                        // For names, try full name first, then partial
                        regex = new RegExp(`\\b${escapedFake}\\b`, 'gi');
                    } else if (mapping.type === 'LOCATION') {
                        // For locations, use exact match with flexible whitespace but NO partial matching
                        // Locations are complex and GPT might reformat them, so we need exact matches only
                        regex = new RegExp(escapedFake.replace(/\s+/g, '\\s+'), 'gi');
                    } else {
                        // For emails, phones, etc., match with flexible whitespace
                        regex = new RegExp(escapedFake.replace(/\s+/g, '\\s+'), 'gi');
                    }
                    
                    if (regex.test(nodeText)) {
                        // Determine replacement value
                        let replacementValue = originalValue;
                        let allowPartialMatch = false;
                        
                        if (mapping.type === 'PERSON' || mapping.type === 'NAME') {
                            const nameParts = fakeValue.split(/\s+/);
                            const originalParts = originalValue.split(/\s+/);
                            
                            // Only allow partial matching if both fake and original have multiple parts
                            if (nameParts.length >= 2 && originalParts.length >= 2) {
                                // Check if we're matching a full name or partial
                                const fullMatch = nodeText.includes(fakeValue);
                                
                                if (!fullMatch) {
                                    // Check for partial matches - be very conservative
                                    const firstName = nameParts[0];
                                    const lastName = nameParts[nameParts.length - 1];
                                    
                                    // Only match if the text contains JUST the first or last name (with word boundaries)
                                    const firstNameRegex = new RegExp(`\\b${firstName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, 'gi');
                                    const lastNameRegex = new RegExp(`\\b${lastName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, 'gi');
                                    
                                    if (firstNameRegex.test(nodeText) && !nodeText.includes(fakeValue)) {
                                        // Check if it's a standalone first name (not part of another name)
                                        const firstNameMatches = nodeText.match(firstNameRegex);
                                        if (firstNameMatches && firstNameMatches.length > 0) {
                                            // Only replace if it's clearly the first name alone
                                            replacementValue = originalParts[0];
                                            allowPartialMatch = true;
                                        }
                                    } else if (lastNameRegex.test(nodeText) && !nodeText.includes(fakeValue)) {
                                        // Check if it's a standalone last name
                                        const lastNameMatches = nodeText.match(lastNameRegex);
                                        if (lastNameMatches && lastNameMatches.length > 0) {
                                            // Only replace if it's clearly the last name alone
                                            replacementValue = originalParts[originalParts.length - 1];
                                            allowPartialMatch = true;
                                        }
                                    }
                                }
                            }
                        }
                        
                        // Replace in this text node
                        nodeText = nodeText.replace(regex, (match) => {
                            // Always prefer full match
                            if (match === fakeValue || match.toLowerCase() === fakeValue.toLowerCase()) {
                                nodeModified = true;
                                // Preserve case of first letter
                                if (match[0] === match[0].toUpperCase() && replacementValue[0]) {
                                    return replacementValue[0].toUpperCase() + replacementValue.slice(1);
                                }
                                return replacementValue;
                            } else if (allowPartialMatch && (mapping.type === 'PERSON' || mapping.type === 'NAME')) {
                                // Only do partial replacement if we explicitly allowed it
                                nodeModified = true;
                                return replacementValue;
                            }
                            return match;
                        });
                    }
                }
                
                // Only update the text node if it was modified
                if (nodeModified) {
                    textNode.textContent = nodeText;
                }
            }
            
            totalReverted++;
        }
    }
    
    console.log(`[PII Extension] Revert complete: ${totalReverted} response elements updated, ${totalReplacements} total replacements`);
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
      // Alert removed per user request
      // alert("Content area not found. Please make sure you're on a supported page.");
      
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
      // Enhanced selectors for ChatGPT/Gemini - try more specific ones first
      const textareaSelectors = [
        // ChatGPT specific selectors
        'textarea#prompt-textarea',
        'textarea[data-id="root"]',
        'textarea[tabindex="0"]',
        'div[contenteditable="true"][data-id="root"]',
        'div[contenteditable="true"][tabindex="0"]',
        'textarea[aria-label*="prompt"]',
        'textarea[aria-label*="Message"]',
        'textarea[aria-label*="message"]',
        'textarea[placeholder*="prompt"]',
        'textarea[placeholder*="Message"]',
        'textarea[placeholder*="message"]',
        'textarea[contenteditable="true"]',
        'div[contenteditable="true"][role="textbox"]',
        'div[contenteditable="true"]',
        // More generic selectors
        'textarea',
        'div[role="textbox"]'
      ];
      
      let textarea = null;
      let foundSelector = null;
      
      for (const selector of textareaSelectors) {
        try {
          const elements = document.querySelectorAll(selector);
          // Try to find the one that's actually visible and has focus or is the input
          for (const el of elements) {
            const rect = el.getBoundingClientRect();
            const isVisible = rect.width > 0 && rect.height > 0;
            const isInput = el.tagName === 'TEXTAREA' || 
                          (el.contentEditable === 'true' && el.getAttribute('role') === 'textbox') ||
                          (el.contentEditable === 'true' && el.hasAttribute('data-id'));
            
            if (isVisible && isInput) {
              textarea = el;
              foundSelector = selector;
              break;
            }
          }
          
          if (textarea) break;
          
          // Fallback: just use the first one if any found
          if (elements.length > 0) {
            textarea = elements[0];
            foundSelector = selector;
            break;
          }
        } catch (e) {
          console.warn(`[PII Extension] Error with selector ${selector}:', e`);
        }
      }
      
      if (textarea) {
        // Try multiple ways to get text
        textToAnalyze = textarea.value || 
                       textarea.textContent || 
                       textarea.innerText || 
                       (textarea.querySelector ? textarea.querySelector('div')?.textContent : '') ||
                       '';
        
        // For contenteditable divs, try to get text from child nodes
        if (!textToAnalyze && textarea.contentEditable === 'true') {
          const walker = document.createTreeWalker(
            textarea,
            NodeFilter.SHOW_TEXT,
            null,
            false
          );
          
          let textNodes = [];
          let node;
          while (node = walker.nextNode()) {
            textNodes.push(node.textContent);
          }
          textToAnalyze = textNodes.join('');
        }
        
        console.log(`[PII Extension] Found textarea with selector: ${foundSelector}`);
        console.log(`[PII Extension] Textarea tag: ${textarea.tagName}, contentEditable: ${textarea.contentEditable}`);
        console.log(`[PII Extension] Extracted ${textToAnalyze.length} characters from input field`);
        console.log(`[PII Extension] Text preview (first 100 chars): "${textToAnalyze.substring(0, 100)}"`);
      } else {
        console.warn('[PII Extension] No textarea found with any selector');
        console.warn('[PII Extension] Available textareas on page:', document.querySelectorAll('textarea').length);
        console.warn('[PII Extension] Available contenteditable divs:', document.querySelectorAll('div[contenteditable="true"]').length);
        textToAnalyze = '';
      }
    } else {
      textToAnalyze = editor.textContent || editor.innerText || '';
    }
    
    if (!textToAnalyze.trim()) {
      // Alert removed per user request
      // alert("No text found to analyze. Please type your message in the input field first.");
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
        // Alert removed per user request
        // alert("⚠️ Backend server not available. Using fallback mode. Please ensure the backend server is running on http://127.0.0.1:5000");
      }
    } catch (error) {
      console.error("[PII Extension] Error detecting PII:", error);
      // Fallback to mock data on error
      piiResults = getMockPIIData(currentModel);
      // Alert removed per user request
      // alert("⚠️ Error connecting to backend. Using fallback mode. Please check if the backend server is running.");
    } finally {
      // Restore button
      scanButton.innerHTML = originalButtonText;
      scanButton.disabled = false;
    }
    
    // Process results and highlight
    if (piiResults && piiResults.detected_entities && piiResults.detected_entities.length > 0) {
        const modelName = MODEL_CONFIGS[currentModel]?.name || currentModel;
        
        // Don't show alert here - let the highlighting function show the final count
        // This ensures consistency between detected and actually highlighted items
        try {
          highlightPiiInDocument(piiResults.detected_entities);
        } catch (highlightError) {
          console.error("[PII Extension] Error highlighting PII:", highlightError);
          // Alert removed per user request
          // alert("PII detected but highlighting failed. Please try again.");
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
        // Alert removed per user request
        // alert(`Scan complete with ${modelName}, no PII found.`);
        
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
    
    // Alert removed per user request
    // alert("An error occurred during scanning. Please try again.");
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
            
            // Show consistent message with model name
            const modelName = MODEL_CONFIGS[currentModel]?.name || currentModel;
            const totalDetected = entities.length;
            
            // Alerts removed per user request
            // if (highlightCount === totalDetected) {
            //     alert(`Scan complete with ${modelName}! Found ${highlightCount} PII items. Click any highlighted text to review and accept/reject.`);
            // } else {
            //     alert(`Scan complete with ${modelName}! Detected ${totalDetected} PII items, highlighted ${highlightCount} (${totalDetected - highlightCount} may be already redacted or not found). Click any highlighted text to review and accept/reject.`);
            // }
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
            // Alert removed per user request
            // alert("No PII found to highlight. Make sure your document contains the sample text.");
        }
    }
}

// ChatGPT/Gemini-specific highlighting that shows inline highlights in the input field
function highlightPiiForChatGPT(entities) {
    try {
        const pageType = detectPageType();
        const isGemini = pageType === 'gemini';
        
        // Use the enhanced textarea finder
        const textareaResult = findChatGPTTextarea();
        
        if (!textareaResult || !textareaResult.textarea) {
            // Alert removed per user request
            // alert(`${isGemini ? 'Gemini' : 'ChatGPT'} input not found. Please make sure you're in the chat interface and have typed a message.`);
            return;
        }
        
        const textarea = textareaResult.textarea;
        let originalText = textareaResult.text;
        
        console.log(`[PII Extension] Found input field with selector: ${textareaResult.selector}`);
        
        if (!originalText || !originalText.trim()) {
            console.warn(`[PII Extension] No text found in ${isGemini ? 'Gemini' : 'ChatGPT'} input field`);
            console.warn(`[PII Extension] Textarea value: "${textarea.value}"`);
            console.warn(`[PII Extension] Textarea textContent: "${textarea.textContent}"`);
            console.warn(`[PII Extension] Textarea innerText: "${textarea.innerText}"`);
            // Alert removed per user request
            // alert(`No text found in ${isGemini ? 'Gemini' : 'ChatGPT'} input. Please type your message in the input field first.`);
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
            
            // Normalize both text and entity value for better matching
            // This handles Unicode normalization issues (e.g., Turkish characters)
            const normalizedText = originalText.normalize('NFC');
            const normalizedEntityValue = entityValue.normalize('NFC');
            
            // Use multiple search strategies for robustness
            let occurrences = [];
            
            // Strategy 1: Exact case-insensitive search
            const lowerText = normalizedText.toLowerCase();
            const lowerEntityValue = normalizedEntityValue.toLowerCase();
            let searchIndex = 0;
            
            while (true) {
                const foundIndex = lowerText.indexOf(lowerEntityValue, searchIndex);
                if (foundIndex === -1) break;
                
                // Get the actual text at this position
                const actualText = normalizedText.substring(foundIndex, foundIndex + normalizedEntityValue.length);
                
                // Verify it matches (case-insensitive, normalized)
                if (actualText.toLowerCase() === lowerEntityValue) {
                    // Check if this position is already redacted
                    if (!isRedactedText(normalizedText, foundIndex, foundIndex + normalizedEntityValue.length)) {
                        // Check if we already have this occurrence (avoid duplicates)
                        const isDuplicate = occurrences.some(occ => 
                            occ.start === foundIndex && occ.end === foundIndex + normalizedEntityValue.length
                        );
                        
                        if (!isDuplicate) {
                            occurrences.push({
                                start: foundIndex,
                                end: foundIndex + normalizedEntityValue.length,
                                value: actualText
                            });
                        }
                    }
                }
                
                searchIndex = foundIndex + 1;
            }
            
            // Strategy 2: If not found, try regex search (more flexible)
            if (occurrences.length === 0) {
                try {
                    // Escape special regex characters
                    const escapedEntity = normalizedEntityValue.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
                    const regex = new RegExp(escapedEntity, 'gi');
                    const matches = [...normalizedText.matchAll(regex)];
                    
                    matches.forEach(match => {
                        const foundIndex = match.index;
                        const actualText = match[0];
                        
                        // Check if this position is already redacted
                        if (!isRedactedText(normalizedText, foundIndex, foundIndex + actualText.length)) {
                            occurrences.push({
                                start: foundIndex,
                                end: foundIndex + actualText.length,
                                value: actualText
                            });
                        }
                    });
                } catch (e) {
                    console.warn(`[PII Extension] Regex search failed for "${entityValue}":`, e);
                }
            }
            
            // Strategy 3: If still not found, try using backend's original offsets as fallback
            if (occurrences.length === 0 && entity.start !== undefined && entity.end !== undefined) {
                // Backend provided offsets - verify if they're still valid
                const backendStart = entity.start;
                const backendEnd = entity.end;
                
                if (backendStart >= 0 && backendEnd <= normalizedText.length && backendEnd > backendStart) {
                    const textAtBackendOffset = normalizedText.substring(backendStart, backendEnd);
                    
                    // Check if the text at backend offset matches (case-insensitive)
                    if (textAtBackendOffset.toLowerCase() === lowerEntityValue) {
                        // Backend offset is still valid
                        if (!isRedactedText(normalizedText, backendStart, backendEnd)) {
                            occurrences.push({
                                start: backendStart,
                                end: backendEnd,
                                value: textAtBackendOffset
                            });
                            console.log(`[PII Extension] Found PII "${entityValue}" using backend offset ${backendStart}-${backendEnd}`);
                        } else {
                            console.warn(`[PII Extension] Backend offset ${backendStart}-${backendEnd} points to already-redacted text`);
                        }
                    } else {
                        // Backend offset doesn't match - text might have changed
                        console.warn(`[PII Extension] Backend offset mismatch: expected "${entityValue}" at ${backendStart}-${backendEnd}, found "${textAtBackendOffset}"`);
                    }
                }
            }
            
            // Strategy 4: If still not found, try with whitespace normalization
            if (occurrences.length === 0) {
                // Remove all whitespace and compare
                const textNoWhitespace = normalizedText.replace(/\s+/g, '');
                const entityNoWhitespace = normalizedEntityValue.replace(/\s+/g, '');
                
                if (textNoWhitespace.includes(entityNoWhitespace)) {
                    // Find position accounting for removed whitespace
                    const lowerTextNoWS = textNoWhitespace.toLowerCase();
                    const lowerEntityNoWS = entityNoWhitespace.toLowerCase();
                    const indexInNoWS = lowerTextNoWS.indexOf(lowerEntityNoWS);
                    
                    if (indexInNoWS !== -1) {
                        // Try to find the actual position in original text
                        // This is approximate but better than nothing
                        const approximateIndex = normalizedText.toLowerCase().indexOf(lowerEntityValue);
                        if (approximateIndex !== -1) {
                            const actualText = normalizedText.substring(approximateIndex, approximateIndex + normalizedEntityValue.length);
                            if (actualText.toLowerCase() === lowerEntityValue && 
                                !isRedactedText(normalizedText, approximateIndex, approximateIndex + normalizedEntityValue.length)) {
                                occurrences.push({
                                    start: approximateIndex,
                                    end: approximateIndex + normalizedEntityValue.length,
                                    value: actualText
                                });
                            }
                        }
                    }
                }
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
                // Enhanced debugging
                console.warn(`[PII Extension] Could not find PII "${entityValue}" in current text`);
                console.warn(`[PII Extension] Entity length: ${entityValue.length}, Text length: ${normalizedText.length}`);
                console.warn(`[PII Extension] Entity (first 50 chars): "${entityValue.substring(0, 50)}"`);
                console.warn(`[PII Extension] Text contains entity (case-insensitive): ${lowerText.includes(lowerEntityValue)}`);
                
                // Try to find partial matches to help debug
                if (normalizedEntityValue.length > 5) {
                    // Check if at least part of the entity exists
                    const firstPart = normalizedEntityValue.substring(0, Math.min(10, normalizedEntityValue.length));
                    const lastPart = normalizedEntityValue.substring(Math.max(0, normalizedEntityValue.length - 10));
                    
                    const firstPartFound = lowerText.includes(firstPart.toLowerCase());
                    const lastPartFound = lowerText.includes(lastPart.toLowerCase());
                    
                    console.warn(`[PII Extension] First part "${firstPart}" found: ${firstPartFound}`);
                    console.warn(`[PII Extension] Last part "${lastPart}" found: ${lastPartFound}`);
                    
                    if (firstPartFound || lastPartFound) {
                        // Try to find where it might be
                        const searchPattern = firstPartFound ? firstPart : lastPart;
                        const searchIndex = lowerText.indexOf(searchPattern.toLowerCase());
                        if (searchIndex !== -1) {
                            const contextStart = Math.max(0, searchIndex - 20);
                            const contextEnd = Math.min(normalizedText.length, searchIndex + searchPattern.length + 20);
                            const context = normalizedText.substring(contextStart, contextEnd);
                            console.warn(`[PII Extension] Found partial match at position ${searchIndex}, context: "${context}"`);
                        }
                    }
                }
                
                // Check if entity might be split across lines or have different whitespace
                const entityWords = normalizedEntityValue.split(/\s+/).filter(w => w.length > 0);
                if (entityWords.length > 1) {
                    const allWordsFound = entityWords.every(word => 
                        lowerText.includes(word.toLowerCase())
                    );
                    if (allWordsFound) {
                        console.warn(`[PII Extension] All words of "${entityValue}" are present in text, but not as a continuous string`);
                    }
                }
                
                // For emails, check if @ symbol might be causing issues
                if (entityType === 'EMAIL' && normalizedEntityValue.includes('@')) {
                    const emailParts = normalizedEntityValue.split('@');
                    if (emailParts.length === 2) {
                        const localPart = emailParts[0];
                        const domainPart = emailParts[1];
                        const localFound = lowerText.includes(localPart.toLowerCase());
                        const domainFound = lowerText.includes(domainPart.toLowerCase());
                        console.warn(`[PII Extension] Email local part "${localPart}" found: ${localFound}`);
                        console.warn(`[PII Extension] Email domain "${domainPart}" found: ${domainFound}`);
                    }
                }
            }
        });
        
        if (foundPII.length === 0) {
            // Alert removed per user request
            // alert(`No PII found in your ${isGemini ? 'Gemini' : 'ChatGPT'} message.`);
            return;
        }
        
        // Store the original text and PII info for later use
        window.chatGPTOriginalText = originalText;
        window.chatGPTFoundPII = foundPII;
        window.chatGPTTextarea = textarea;
        
        // Create inline overlay highlights for each PII item
        createInlineHighlightsForTextarea(textarea, foundPII, originalText);
        
        // Show consistent info message with model name
        const modelName = MODEL_CONFIGS[currentModel]?.name || 'Presidio';
        const totalDetected = entities.length;
        const totalHighlighted = foundPII.length;
        
        // Alerts removed per user request
        // if (totalHighlighted === totalDetected) {
        //     alert(`Scan complete with ${modelName}! Found ${totalHighlighted} PII items. Click any yellow highlight to accept or reject individually.`);
        // } else {
        //     alert(`Scan complete with ${modelName}! Detected ${totalDetected} PII items, highlighted ${totalHighlighted} (${totalDetected - totalHighlighted} filtered out - may be already redacted). Click any yellow highlight to accept or reject individually.`);
        // }
        
    } catch (error) {
        console.error("[PII Extension] Error in chat interface PII analysis:", error);
        const pageType = detectPageType();
        // Alert removed per user request
        // alert(`Error analyzing ${pageType === 'gemini' ? 'Gemini' : 'ChatGPT'} text. Please try again.`);
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
 * Remove overlapping spans to prevent offset calculation errors
 * When spans overlap, keep the one that starts first and is longest
 * 
 * @param {Array} spans - Array of {start, end, entity} objects
 * @returns {Array} Non-overlapping spans array
 */
function removeOverlappingSpans(spans) {
    if (spans.length === 0) return [];
    
    // Sort by start position, then by length (longest first) for same start
    const sorted = [...spans].sort((a, b) => {
        if (a.start !== b.start) {
            return a.start - b.start;
        }
        // If same start, prefer longer span
        return (b.end - b.start) - (a.end - a.start);
    });
    
    const nonOverlapping = [];
    
    for (const span of sorted) {
        // Check if this span overlaps with any already added span
        let overlaps = false;
        for (const existing of nonOverlapping) {
            // Check if spans overlap: one starts before the other ends
            if (span.start < existing.end && span.end > existing.start) {
                overlaps = true;
                break;
            }
        }
        
        if (!overlaps) {
            nonOverlapping.push(span);
        }
    }
    
    return nonOverlapping;
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
        // Alert removed per user request
        // alert("Input field not found. Please try scanning again.");
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
            // Alert removed per user request
            // alert(`Error: Could not find "${piiValue}" in the text. The text may have been modified.`);
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
    
    // Remove this overlay and all related overlays for this PII (in case of multi-line)
    // Find all overlays with the same PII value and position, remove them
    document.querySelectorAll('.pii-textarea-overlay').forEach(overlay => {
        const overlayValue = overlay.getAttribute('data-pii-value');
        const overlayStart = parseInt(overlay.getAttribute('data-pii-start'));
        const overlayEnd = parseInt(overlay.getAttribute('data-pii-end'));
        
        // Check if this overlay matches the rejected PII
        if (overlayValue === piiValue && overlayStart === start && overlayEnd === end) {
            if (overlay._updatePosition) {
                window.removeEventListener('scroll', overlay._updatePosition, true);
                window.removeEventListener('resize', overlay._updatePosition);
            }
            overlay.remove();
        }
    });
    
    // Remove this PII from the list
    window.chatGPTFoundPII = window.chatGPTFoundPII.filter(p => 
        !(p.start === start && p.end === end && p.value === piiValue)
    );
    
    // Remove the popup
    popup.remove();
    
    console.log(`[PII Extension] Rejected: ${piiType} "${piiValue}" - highlights removed`);
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
            // Alert removed per user request
            // alert("Please scan for PII first.");
            return;
        }
        
        // Get current text from textarea (may have been modified)
        const currentText = textarea.value || textarea.textContent || window.chatGPTOriginalText || '';
        
        // Find actual positions of PII in current text (similar to highlighting logic)
        // This ensures we redact the correct text even if it has been modified
        const spans = [];
        const lowerText = currentText.toLowerCase();
        const addedSpans = new Set(); // Track added spans to avoid duplicates
        
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
                    
                    // Create a unique key for this span position
                    const spanKey = `${foundIndex}-${foundIndex + piiValue.length}`;
                    
                    // Check if we've already added this exact span
                    if (!addedSpans.has(spanKey)) {
                        spans.push({
                            start: foundIndex,
                            end: foundIndex + piiValue.length,
                            entity: {
                                type: pii.type,
                                value: actualText
                            }
                        });
                        addedSpans.add(spanKey);
                    }
                }
                
                searchIndex = foundIndex + 1;
            }
        });
        
        if (spans.length === 0) {
            // Alert removed per user request
            // alert("No PII found to redact. The text may have been modified or already redacted.");
            return;
        }
        
        // Remove overlapping spans to prevent offset calculation errors
        // This is critical - overlapping spans cause nested/incorrect redaction tags
        const nonOverlappingSpans = removeOverlappingSpans(spans);
        
        if (nonOverlappingSpans.length === 0) {
            // Alert removed per user request
            // alert("No PII found to redact after removing overlaps. The text may have been modified or already redacted.");
            return;
        }
        
        // Sort spans by start position (required for offset tracking)
        nonOverlappingSpans.sort((a, b) => a.start - b.start);
        
        // Create mask function
        const maskFor = (entity) => {
            return getRedactionLabel(entity.type);
        };
        
        // Use the new offset tracking system to redact all PII
        // This ensures offsets are correctly maintained after each redaction
        const result = redactPIIWithOffsetTracking(currentText, nonOverlappingSpans, maskFor);
        
        console.log(`[PII Extension] Redacted ${nonOverlappingSpans.length} PII items using offset tracking system (${spans.length} total found, ${spans.length - nonOverlappingSpans.length} overlaps removed)`);
        console.log(`[PII Extension] Original text length: ${currentText.length}, Redacted length: ${result.text.length}`);
        
        // Store mappings for original PII -> masked version (for future fake data filling)
        // This allows us to track: original -> masked -> fake
        nonOverlappingSpans.forEach((span, index) => {
            const mappingId = generatePIIMappingId();
            const maskedLabel = getRedactionLabel(span.entity.type);
            const mapping = {
                id: mappingId,
                original: span.entity.value, // Original PII value
                masked: maskedLabel, // The redaction label like [NAME]
                fake: null, // Will be filled when user clicks Fill button
                type: span.entity.type,
                position: span.start, // Position in original text
                timestamp: Date.now()
            };
            
            window.piiMapping.set(mappingId, mapping);
            console.log(`[PII Extension] Pre-stored mapping for future fill: ${mapping.original} -> ${mapping.masked}`);
        });
        
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
            
            // Alert removed per user request
            // alert(`Successfully redacted ${nonOverlappingSpans.length} PII items. Your message is ready to send.`);
            
            // Keep stored data for fill operation (don't delete yet)
            // We'll clean it up after fill or when user sends message
            // delete window.chatGPTOriginalText;
            // delete window.chatGPTFoundPII;
            // delete window.chatGPTTextarea;
        } else {
            // Alert removed per user request
            // alert(`Failed to update ${isGemini ? 'Gemini' : 'ChatGPT'} input. Please try again.`);
        }
        
    } catch (error) {
        console.error("[PII Extension] Error in chat interface accept all:", error);
        // Alert removed per user request
        // alert("Error redacting PII. Please try again.");
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
        // Alert removed per user request
        // alert(`Overlay highlighting complete! Found ${highlightCount} PII suggestions. Click yellow boxes to review and accept/reject.`);
    } else {
        // Alert removed per user request
        // alert("Could not create overlay highlights. The text might not be accessible for positioning.");
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
// ============================================================================
// MESSAGE SEND DETECTION AND HIGHLIGHT CLEANUP
// ============================================================================

/**
 * Detects when a message is sent and clears highlights from input field
 * Also ensures highlights don't appear in sent messages
 */
function setupMessageSendDetection() {
    const pageType = detectPageType();
    
    if (pageType !== 'chatgpt' && pageType !== 'gemini') {
        return; // Only needed for chat interfaces
    }
    
    console.log(`[PII Extension] Setting up message send detection for ${pageType}`);
    
    // Strategy 1: Listen for send button clicks
    const sendButtonSelectors = [
        'button[data-testid="send-button"]',
        'button[aria-label*="Send"]',
        'button[aria-label*="send"]',
        '[data-testid="send-button"]',
        'button[type="submit"]',
        'button.send-button',
        'button[class*="send"]'
    ];
    
    // Function to clear highlights from input field
    const clearInputHighlights = () => {
        console.log('[PII Extension] Clearing highlights from input field after message send');
        
        // Remove all textarea overlay highlights
        document.querySelectorAll('.pii-textarea-overlay').forEach(el => {
            if (el._updatePosition) {
                window.removeEventListener('scroll', el._updatePosition, true);
                window.removeEventListener('resize', el._updatePosition);
            }
            el.remove();
        });
        
        // Remove suggestion popups
        document.querySelectorAll('.pii-suggestion-popup').forEach(popup => {
            popup.remove();
        });
        
        // Clear stored data
        delete window.chatGPTOriginalText;
        delete window.chatGPTFoundPII;
        delete window.chatGPTTextarea;
    };
    
    // Add click listeners to send buttons
    const addSendButtonListeners = () => {
        sendButtonSelectors.forEach(selector => {
            try {
                const buttons = document.querySelectorAll(selector);
                buttons.forEach(button => {
                    // Only add listener if not already added
                    if (!button.dataset.piiListenerAdded) {
                        button.addEventListener('click', () => {
                            console.log('[PII Extension] Send button clicked, clearing highlights');
                            // Small delay to ensure message is sent
                            setTimeout(clearInputHighlights, 100);
                        }, { once: false });
                        button.dataset.piiListenerAdded = 'true';
                    }
                });
            } catch (e) {
                // Ignore errors
            }
        });
    };
    
    // Initial setup
    addSendButtonListeners();
    
    // Re-setup when DOM changes (for dynamic send buttons)
    const sendButtonObserver = new MutationObserver(() => {
        addSendButtonListeners();
    });
    
    sendButtonObserver.observe(document.body, {
        childList: true,
        subtree: true
    });
    
    // Strategy 2: Monitor input field for clearing (when it becomes empty after send)
    const monitorInputField = () => {
        const textareaSelectors = [
            'textarea[aria-label*="prompt"]',
            'textarea[aria-label*="message"]',
            'textarea[placeholder*="prompt"]',
            'textarea[placeholder*="message"]',
            'textarea[contenteditable="true"]',
            'div[contenteditable="true"][role="textbox"]',
            'textarea'
        ];
        
        let lastText = '';
        let lastTextLength = 0;
        
        const checkInputField = () => {
            let textarea = null;
            for (const selector of textareaSelectors) {
                textarea = document.querySelector(selector);
                if (textarea) break;
            }
            
            if (textarea) {
                const currentText = textarea.value || textarea.textContent || '';
                const currentLength = currentText.length;
                
                // If text was cleared (went from non-empty to empty), message was likely sent
                if (lastTextLength > 0 && currentLength === 0 && lastText !== currentText) {
                    console.log('[PII Extension] Input field cleared, message likely sent');
                    clearInputHighlights();
                }
                
                lastText = currentText;
                lastTextLength = currentLength;
            }
        };
    
        // Check periodically
        setInterval(checkInputField, 500);
    };
    
    monitorInputField();
    
    // Strategy 3: Monitor chat history to ensure no highlights appear in sent messages
    const monitorChatHistory = () => {
        const chatHistoryObserver = new MutationObserver((mutations) => {
            // Check for new message elements being added
            mutations.forEach(mutation => {
                mutation.addedNodes.forEach(node => {
                    if (node.nodeType === Node.ELEMENT_NODE) {
                        // Remove any highlights from newly added messages
                        const highlights = node.querySelectorAll ? node.querySelectorAll('.pii-textarea-overlay, .pii-highlight, .pii-overlay-highlight') : [];
                        highlights.forEach(highlight => {
                            console.log('[PII Extension] Removing highlight from sent message');
                            highlight.remove();
                        });
                        
                        // Also check if the node itself is a highlight
                        if (node.classList && (
                            node.classList.contains('pii-textarea-overlay') ||
                            node.classList.contains('pii-highlight') ||
                            node.classList.contains('pii-overlay-highlight')
                        )) {
                            // Check if it's in a message bubble (sent message)
                            let parent = node.parentElement;
                            let isInMessage = false;
                            while (parent) {
                                if (parent.classList && (
                                    parent.classList.contains('message') ||
                                    parent.classList.contains('chat-message') ||
                                    parent.getAttribute('data-message-id') ||
                                    parent.getAttribute('data-testid')?.includes('message')
                                )) {
                                    isInMessage = true;
                                    break;
                                }
                                parent = parent.parentElement;
                            }
                            
                            if (isInMessage) {
                                console.log('[PII Extension] Removing highlight from sent message bubble');
                                node.remove();
                            }
                        }
                    }
                });
            });
        });
        
        // Observe the entire document for new message additions
        chatHistoryObserver.observe(document.body, {
            childList: true,
            subtree: true
        });
    };
    
    monitorChatHistory();
    
    console.log('[PII Extension] Message send detection setup complete');
}

// ============================================================================
// END MESSAGE SEND DETECTION
// ============================================================================

function initializePiiDetector() {
  const pageType = detectPageType();
  console.log(`Detected page type: ${pageType}`);
  
  // Ensure document.body is available
  if (document.body) {
    injectScanButton();
    // Setup message send detection for chat interfaces
    setupMessageSendDetection();
  } else {
    // Wait for body to be available
    const observer = new MutationObserver((mutations, obs) => {
      if (document.body) {
        injectScanButton();
        // Setup message send detection for chat interfaces
        setupMessageSendDetection();
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

