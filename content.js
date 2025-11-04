// --- MOCK MODE: API Connection Disabled ---
// This script uses fake data for PII detection and includes highlighting logic.
console.log("PII Detector Content Script Loaded! (MOCK MODE)");

// Highlighting class (must synchronize with style.css)
const HIGHLIGHT_CLASS = 'pii-highlight'; 
const REDACT_BTN_CLASS = 'pii-redact-btn';

// Mock PII data matching the user's document text for testing highlighting
const MOCK_PII_DATA = {
  "has_pii": true,
  "detected_entities": [
    // Based on the actual ChatGPT text:
    // "I am İde, living in Tuzla with my friend Neris Yılmaz. I will present this to my professors Dr. Emre Gürsoy and Dr. Saygın..."
    
    // Names (PERSON) - exact matches from ChatGPT
    { "type": "PERSON", "start": 5, "end": 8, "value": "İde" },
    { "type": "PERSON", "start": 42, "end": 54, "value": "Neris Yılmaz" },
    { "type": "PERSON", "start": 94, "end": 109, "value": "Dr. Emre Gürsoy" },
    { "type": "PERSON", "start": 114, "end": 124, "value": "Dr. Saygın" },
    
    // Locations (LOCATION) 
    { "type": "LOCATION", "start": 20, "end": 25, "value": "Tuzla" },
    { "type": "LOCATION", "start": 139, "end": 147, "value": "İstanbul" },
    { "type": "LOCATION", "start": 150, "end": 157, "value": "Türkiye" },
    { "type": "LOCATION", "start": 206, "end": 214, "value": "Orta Mah" },
    { "type": "LOCATION", "start": 216, "end": 230, "value": "Üniversite Cad" },
    { "type": "LOCATION", "start": 237, "end": 254, "value": "Sabancı Üniversitesi" },
    
    // Phone number (PHONE)
    { "type": "PHONE", "start": 180, "end": 193, "value": "545 333 66 78" },
    
    // Emails (EMAIL) - exact from ChatGPT
    { "type": "EMAIL", "start": 290, "end": 319, "value": "yücel.saygin@sabanciuniv.edu" },
    { "type": "EMAIL", "start": 321, "end": 342, "value": "emregursoy@gmail.com" },
    
    // Alternative spellings that might appear
    { "type": "PERSON", "start": 5, "end": 8, "value": "Ide" }, // without dot
    { "type": "LOCATION", "start": 139, "end": 147, "value": "Istanbul" }, // without dot
  ],
  "total_entities": 15
};

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
    
    container.appendChild(scanButton);
    container.appendChild(clearButton);
    
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
    let textHighlightCount = 0;
    
    if (editor) {
        // Find highlighted spans
        highlightedElements = editor.querySelectorAll(`.${HIGHLIGHT_CLASS}`);
        textHighlightCount = highlightedElements.length;
        
        if (textHighlightCount > 0) {
            // Replace each highlight span with its text content
            highlightedElements.forEach(el => {
                const textNode = document.createTextNode(el.textContent);
                el.parentNode.replaceChild(textNode, el);
            });
        }
    }
    
    // Clear overlay highlights
    const overlayElements = document.querySelectorAll('.pii-overlay-highlight');
    overlayElements.forEach(el => el.remove());
    
    const totalCleared = textHighlightCount + overlayElements.length;
    
    // Only show alert if explicitly requested and there were highlights to clear
    if (showAlert && totalCleared > 0) {
        alert(`Highlights cleared. (${textHighlightCount} text highlights + ${overlayElements.length} overlay highlights)`);
    } else if (showAlert && totalCleared === 0) {
        alert("No highlights to clear.");
    }
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
  
  // 1. Use MOCK Data
  const piiResults = MOCK_PII_DATA;
  
  // 2. Process results and highlight
  if (piiResults && piiResults.detected_entities && piiResults.detected_entities.length > 0) {
      alert(`Scan complete! ${piiResults.total_entities} PII items found. Click the highlighted words to Redact.`);
      highlightPiiInDocument(piiResults.detected_entities);
  } else {
      alert("Scan complete, no PII found.");
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
        
        // Create the highlight HTML structure
        const highlightHTML = `<span class="${HIGHLIGHT_CLASS}" data-pii-type="${entity.type}" data-pii-value="${entity.value}">$1</span>`;
        
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
            
            alert(`Highlighting complete! Found and highlighted ${highlightCount} PII instances. Click any highlighted text to redact it.`);
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
        highlightSpan.style.backgroundColor = '#ffeb3b';
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

// Adds click listeners to the highlighted PII spans
function addRedactEvents() {
    document.querySelectorAll(`.${HIGHLIGHT_CLASS}`).forEach(el => {
        el.onclick = (event) => {
            event.stopPropagation(); // Prevents interference with Docs editor
            handleRedactClick(el);
        };
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
        alert(`Overlay highlighting complete! Found ${highlightCount} PII items with yellow highlights.`);
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

// Create an overlay highlight element
function createOverlayHighlight(rect, entity) {
    const overlay = document.createElement('div');
    overlay.className = 'pii-overlay-highlight';
    overlay.setAttribute('data-pii-type', entity.type);
    overlay.setAttribute('data-pii-value', entity.value);
    
    overlay.style.position = 'absolute';
    overlay.style.left = rect.left + 'px';
    overlay.style.top = rect.top + 'px';
    overlay.style.width = rect.width + 'px';
    overlay.style.height = rect.height + 'px';
    overlay.style.backgroundColor = 'rgba(255, 235, 59, 0.7)'; // Yellow with transparency
    overlay.style.border = '2px solid #FFA000';
    overlay.style.borderRadius = '3px';
    overlay.style.pointerEvents = 'auto';
    overlay.style.cursor = 'pointer';
    overlay.style.zIndex = '999999';
    overlay.style.boxSizing = 'border-box';
    
    // Add click handler for redaction
    overlay.onclick = (event) => {
        event.stopPropagation();
        handleOverlayRedact(overlay);
    };
    
    // Add tooltip
    overlay.title = `Click to redact ${entity.type}: ${entity.value}`;
    
    document.body.appendChild(overlay);
}

// Handle redaction for overlay highlights
function handleOverlayRedact(overlay) {
    const piiValue = overlay.getAttribute('data-pii-value');
    const piiType = overlay.getAttribute('data-pii-type');
    
    // Change overlay to show it's redacted
    overlay.style.backgroundColor = 'rgba(244, 67, 54, 0.7)'; // Red
    overlay.style.border = '2px solid #D32F2F';
    overlay.innerHTML = `<span style="color: white; font-weight: bold; font-size: 12px; padding: 2px;">[REDACTED ${piiType}]</span>`;
    overlay.onclick = null; // Remove click handler
    overlay.style.cursor = 'default';
    
    console.log(`Redacted overlay: ${piiType} - "${piiValue}"`);
    alert(`Redacted ${piiType}: ${piiValue}`);
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
