// --- MOCK MODE: API Connection Disabled ---
// This script uses fake data for PII detection and includes highlighting logic.
console.log("PII Detector Content Script Loaded! (MOCK MODE)");

// Highlighting class (must synchronize with style.css)
const HIGHLIGHT_CLASS = 'pii-highlight'; 
const REDACT_BTN_CLASS = 'pii-redact-btn';
const SUGGESTION_POPUP_CLASS = 'pii-suggestion-popup';
const REJECTED_CLASS = 'pii-rejected';

// Track suggestion states
const suggestionStates = new Map(); // Store accept/reject decisions

// Current selected model for PII detection
let currentModel = 'piranha'; // Default model

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

// Mock PII data matching the user's document text for testing highlighting
// Different models detect different amounts and types of PII
function getMockPIIData(model = 'piranha') {
    const baseEntities = [
        // Names (PERSON) - detected by all models
        { "type": "PERSON", "start": 5, "end": 8, "value": "İde" },
        { "type": "PERSON", "start": 42, "end": 54, "value": "Neris Yılmaz" },
        { "type": "PERSON", "start": 94, "end": 109, "value": "Dr. Emre Gürsoy" },
        { "type": "PERSON", "start": 114, "end": 124, "value": "Dr. Saygın" },
        
        // Phone number (PHONE) - detected by most models
        { "type": "PHONE", "start": 180, "end": 193, "value": "545 333 66 78" },
        
        // Emails (EMAIL) - detected by all models
        { "type": "EMAIL", "start": 286, "end": 313, "value": "ide.melisa.yigit@sabanciuniv.edu" },
        { "type": "EMAIL", "start": 316, "end": 337, "value": "neris.ylmz@gmail.com" }
    ];

    const locationEntities = [
        // Locations (LOCATION) - detected by some models
        { "type": "LOCATION", "start": 20, "end": 25, "value": "Tuzla" },
        { "type": "LOCATION", "start": 139, "end": 147, "value": "İstanbul" },
        { "type": "LOCATION", "start": 150, "end": 157, "value": "Türkiye" },
        { "type": "LOCATION", "start": 206, "end": 214, "value": "Orta Mah" },
        { "type": "LOCATION", "start": 216, "end": 230, "value": "Üniversite Cad" },
        { "type": "LOCATION", "start": 237, "end": 254, "value": "Sabancı Üniversitesi" }
    ];

    const sensitiveEntities = [
        // Additional sensitive data detected by advanced models
        { "type": "ID", "start": 400, "end": 411, "value": "12345678901" }, // Turkish ID simulation
        { "type": "ORGANIZATION", "start": 237, "end": 254, "value": "Sabancı Üniversitesi" }
    ];

    let detectedEntities = [...baseEntities];
    
    switch(model) {
        case 'piranha':
            // Aggressive detection - finds almost everything
            detectedEntities = [...baseEntities, ...locationEntities, ...sensitiveEntities];
            break;
            
        case 'presidio':
            // Very high accuracy - finds names, emails, phones, and some locations
            detectedEntities = [...baseEntities, ...locationEntities.slice(0, 3)];
            break;
            
        case 'ai4privacy':
            // Privacy-focused - conservative but thorough
            detectedEntities = [...baseEntities, ...sensitiveEntities];
            break;
            
        case 'bdmbz':
            // Fast but basic - only obvious PII
            detectedEntities = baseEntities.slice(0, 6); // Names, phone, emails only
            break;
            
        case 'nemo':
            // Precision-targeted - high confidence only
            detectedEntities = [...baseEntities, ...locationEntities.slice(0, 2), sensitiveEntities[1]];
            break;
            
        default:
            detectedEntities = baseEntities;
    }

    return {
        "has_pii": detectedEntities.length > 0,
        "detected_entities": detectedEntities,
        "total_entities": detectedEntities.length,
        "model_used": model,
        "confidence_threshold": model === 'bdmbz' ? 0.9 : model === 'piranha' ? 0.6 : 0.8
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
      
    case 'chatgpt':
      contentSelectors = [
        '[data-message-author-role="user"]', // User messages
        '[data-testid="conversation-turn-content"]', // Conversation content
        '.markdown prose', // Message content with markdown
        'article[data-testid^="conversation-turn"]', // Full conversation turns
        '.text-message', // Text messages
        'main [role="main"]', // Main content area
        'main', // Main element as fallback
        '.text-base' // Generic text (last resort)
      ];
      break;
      
    case 'gmail':
      contentSelectors = [
        '.ii.gt .a3s',
        '.ii.gt',
        '[role="textbox"]',
        '.Am.Al.editable'
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
  
  // Try each selector
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
        } else if (pageType === 'chatgpt') {
          // For ChatGPT, check if content contains our PII
          const combinedText = textNodes.map(n => n.textContent).join(' ');
          console.log(`ChatGPT content sample: "${combinedText.substring(0, 100)}"`);
          if (combinedText.includes('İde') || combinedText.includes('Tuzla') || combinedText.includes('Neris') || 
              combinedText.includes('emregursoy@gmail.com') || combinedText.includes('yücel.saygin')) {
            console.log(`Found ChatGPT conversation content using selector: ${selector}`);
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
  
  // Special handling for ChatGPT: search through all conversation elements
  if (pageType === 'chatgpt') {
    console.log("Primary ChatGPT selectors failed, searching all conversation elements...");
    
    // Look for any element containing our PII text
    const allElements = document.querySelectorAll('div, article, section, p, span');
    for (const element of allElements) {
      const text = element.textContent || '';
      if (text.includes('İde') || text.includes('Tuzla') || text.includes('Neris') || 
          text.includes('emregursoy@gmail.com') || text.includes('yücel.saygin')) {
        
        // Make sure this element has sufficient content and isn't just a fragment
        if (text.length > 50) {
          console.log(`Found ChatGPT content in element: ${element.tagName}.${element.className}`);
          console.log(`Content sample: "${text.substring(0, 200)}"`);
          return element;
        }
      }
    }
  }
  
  // Fallback: use document.body
  console.log("Using document.body as fallback");
  return document.body;
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
    // Clear regular highlights by replacing HTML
    const editor = findContentArea();
    let highlightedElements = [];
    let redactedElements = [];
    let textHighlightCount = 0;
    
    if (editor) {
        // Find highlighted spans
        highlightedElements = editor.querySelectorAll(`.${HIGHLIGHT_CLASS}`);
        textHighlightCount = highlightedElements.length;
        
        // Find redacted spans
        redactedElements = editor.querySelectorAll('.pii-redacted');
        
        // Replace highlights with original text
        if (textHighlightCount > 0) {
            highlightedElements.forEach(el => {
                const textNode = document.createTextNode(el.textContent);
                el.parentNode.replaceChild(textNode, el);
            });
        }
        
        // Replace redacted items with original text
        if (redactedElements.length > 0) {
            redactedElements.forEach(el => {
                const originalValue = el.getAttribute('data-original-value') || el.textContent;
                const textNode = document.createTextNode(originalValue);
                el.parentNode.replaceChild(textNode, el);
            });
        }
    }
    
    // Clear overlay highlights
    const overlayElements = document.querySelectorAll('.pii-overlay-highlight');
    overlayElements.forEach(el => el.remove());
    
    // Clear any open suggestion popups
    document.querySelectorAll(`.${SUGGESTION_POPUP_CLASS}`).forEach(popup => popup.remove());
    
    // Reset suggestion states
    suggestionStates.clear();
    
    const totalCleared = textHighlightCount + redactedElements.length + overlayElements.length;
    
    // Only show alert if explicitly requested and there were highlights to clear
    if (showAlert && totalCleared > 0) {
        alert(`All highlights and redactions cleared. (${textHighlightCount} highlights + ${redactedElements.length} redactions + ${overlayElements.length} overlays)`);
    } else if (showAlert && totalCleared === 0) {
        alert("No highlights to clear.");
    }
}

// Accept all detected PII suggestions automatically
function acceptAllPII() {
    console.log("Accept All PII initiated...");
    
    // Get all highlighted PII elements that haven't been processed yet
    const piiHighlights = document.querySelectorAll('.pii-highlight');
    const overlayElements = document.querySelectorAll('[data-pii-overlay]');
    
    let acceptedCount = 0;
    
    // Process regular text highlights
    piiHighlights.forEach(highlight => {
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
            
            // Replace the highlight with redacted text
            highlight.parentNode.replaceChild(redactedSpan, highlight);
            acceptedCount++;
        }
    });
    
    // Process overlay elements
    overlayElements.forEach(overlay => {
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
    });
    
    // Clear any open suggestion popups
    const existingPopup = document.getElementById('pii-suggestion-popup');
    if (existingPopup) {
        existingPopup.remove();
    }
    
    // Show confirmation
    if (acceptedCount > 0) {
        alert(`Successfully accepted and redacted ${acceptedCount} PII elements.`);
    } else {
        alert("No PII detected to accept. Please scan for PII first.");
    }
    
    console.log(`Accept All completed. ${acceptedCount} PII elements processed.`);
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
  console.log("Scan initiated...");
  
  // Clear previous highlights silently before starting new scan
  clearHighlights(false);
  
  const editor = findContentArea();
  if (!editor) {
    alert("Content area not found. Please make sure you're on a supported page.");
    return;
  }
  
  // 1. Use MOCK Data based on current model
  const piiResults = getMockPIIData(currentModel);
  
  // 2. Process results and highlight
  if (piiResults && piiResults.detected_entities && piiResults.detected_entities.length > 0) {
      alert(`Scan complete with ${MODEL_CONFIGS[currentModel].name}! ${piiResults.total_entities} PII suggestions found. Click highlighted text to review and accept/reject each suggestion.`);
      highlightPiiInDocument(piiResults.detected_entities);
  } else {
      alert(`Scan complete with ${MODEL_CONFIGS[currentModel].name}, no PII found.`);
  }
}

// The core function to highlight PII using safe regex-based HTML replacement
function highlightPiiInDocument(entities) {
    const editor = findContentArea();
    if (!editor) {
        console.warn("Cannot highlight PII: Content area not found");
        return;
    }

    const pageType = detectPageType();
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
    const piiValue = highlightElement.getAttribute('data-pii-value');
    const piiType = highlightElement.getAttribute('data-pii-type');
    
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
    
    // Replace the highlight with redacted version
    highlightElement.parentNode.replaceChild(redactedSpan, highlightElement);
    
    // Remove popup
    popup.remove();
    
    console.log(`Accepted suggestion: ${piiType} "${piiValue}" -> "${redactionLabel}"`);
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
