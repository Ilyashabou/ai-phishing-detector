// Listen for navigation events
chrome.webNavigation.onCommitted.addListener(function(details) {
  // Only check main frame navigations (not iframes)
  if (details.frameId === 0) {
    const url = details.url;
    
    // Skip browser internal pages
    if (url.startsWith('chrome://') || url.startsWith('chrome-extension://') || 
        url.startsWith('about:') || url.startsWith('edge://')) {
      return;
    }
    
    // Check if auto-block is enabled
    chrome.storage.sync.get(['autoBlock', 'apiUrl'], function(items) {
      if (items.autoBlock) {
        // Check if we already have a cached result
        chrome.storage.local.get([url], function(result) {
          // In the onCommitted listener
          if (result[url] && result[url].is_phishing && !result[url].temporarily_allowed) {
            // This is a known phishing site, block it
            blockPhishingSite(details.tabId, url);
          }
          
          // In the checkUrl function
          if (data.is_phishing) {
            blockPhishingSite(tabId, url);
          }
          else if (!result[url]) {
            // We don't have a cached result, check the URL
            checkUrl(url, details.tabId, items.apiUrl || 'http://localhost:8000/predict');
          }
        });
      }
    });
  }
});

function checkUrl(url, tabId, apiUrl) {
  fetch(`${apiUrl}?url=${encodeURIComponent(url)}`)
    .then(response => response.json())
    .then(data => {
      // Cache the result
      chrome.storage.local.set({[url]: data});
      
      // If it's a phishing site and auto-block is enabled, block it
      if (data.is_phishing) {
        blockPhishingSite(tabId);
      }
    })
    .catch(error => {
      console.error('Error checking URL:', error);
    });
}

function blockPhishingSite(tabId, url) {
  // Redirect to a warning page with the URL as a parameter
  chrome.tabs.update(tabId, {
    url: chrome.runtime.getURL(`blocked.html?url=${encodeURIComponent(url)}`)
  });
}

// Update extension icon based on current tab
chrome.tabs.onActivated.addListener(function(activeInfo) {
  chrome.tabs.get(activeInfo.tabId, function(tab) {
    updateIcon(tab.url);
  });
});

chrome.tabs.onUpdated.addListener(function(tabId, changeInfo, tab) {
  if (changeInfo.url) {
    updateIcon(changeInfo.url);
  }
});

function updateIcon(url) {
  // Skip browser internal pages
  if (url.startsWith('chrome://') || url.startsWith('chrome-extension://') || 
      url.startsWith('about:') || url.startsWith('edge://')) {
    return;
  }
  
  // Check if we have a cached result
  chrome.storage.local.get([url], function(result) {
    if (result[url]) {
      // Update icon based on result
      const iconPath = result[url].is_phishing ? 
        {16: 'icons/warning16.png', 48: 'icons/warning48.png', 128: 'icons/warning128.png'} :
        {16: 'icons/safe16.png', 48: 'icons/safe48.png', 128: 'icons/safe128.png'};
      
      chrome.action.setIcon({path: iconPath});
    } else {
      // Reset to default icon
      chrome.action.setIcon({
        path: {16: 'icons/icon16.png', 48: 'icons/icon48.png', 128: 'icons/icon128.png'}
      });
    }
  });
}