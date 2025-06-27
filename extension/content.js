// This script runs in the context of web pages

// Listen for messages from the background script
chrome.runtime.onMessage.addListener(function(message, sender, sendResponse) {
  if (message.action === 'showWarning') {
    showPhishingWarning();
    sendResponse({success: true});
  }
});

function showPhishingWarning() {
  // Create warning banner
  const banner = document.createElement('div');
  banner.style.position = 'fixed';
  banner.style.top = '0';
  banner.style.left = '0';
  banner.style.width = '100%';
  banner.style.backgroundColor = '#e74c3c';
  banner.style.color = 'white';
  banner.style.padding = '15px';
  banner.style.textAlign = 'center';
  banner.style.fontWeight = 'bold';
  banner.style.zIndex = '9999';
  banner.style.fontSize = '16px';
  banner.style.boxShadow = '0 2px 10px rgba(0,0,0,0.2)';
  
  banner.innerHTML = `
    ⚠️ WARNING: This website has been detected as a potential phishing site. 
    Be careful with any information you provide. 
    <button id="phishing-warning-close" style="margin-left: 15px; padding: 5px 10px; background: white; color: #e74c3c; border: none; border-radius: 4px; cursor: pointer;">Dismiss</button>
  `;
  
  document.body.prepend(banner);
  
  // Add event listener to close button
  document.getElementById('phishing-warning-close').addEventListener('click', function() {
    banner.remove();
  });
}