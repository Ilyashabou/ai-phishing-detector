document.addEventListener('DOMContentLoaded', function() {
  // Tab switching functionality
  const tabs = document.querySelectorAll('.tab');
  const tabContents = document.querySelectorAll('.tab-content');
  
  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      // Remove active class from all tabs and contents
      tabs.forEach(t => t.classList.remove('active'));
      tabContents.forEach(c => c.classList.remove('active'));
      
      // Add active class to clicked tab and corresponding content
      tab.classList.add('active');
      const tabId = tab.getAttribute('data-tab');
      document.getElementById(`${tabId}-tab`).classList.add('active');
    });
  });
  
  // Load settings
  const apiUrlInput = document.getElementById('api-url');
  const autoBlockCheckbox = document.getElementById('auto-block');
  
  chrome.storage.sync.get(['apiUrl', 'autoBlock'], function(items) {
    if (items.apiUrl) {
      apiUrlInput.value = items.apiUrl;
    }
    if (items.autoBlock !== undefined) {
      autoBlockCheckbox.checked = items.autoBlock;
    }
  });
  
  // Save settings
  document.getElementById('save-settings').addEventListener('click', function() {
    const apiUrl = apiUrlInput.value.trim();
    const autoBlock = autoBlockCheckbox.checked;
    
    chrome.storage.sync.set({ apiUrl, autoBlock }, function() {
      alert('Settings saved!');
    });
  });
  
  // Get current tab URL
  chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
    const url = tabs[0].url;
    document.getElementById('url').textContent = url;
    
    // Check if this URL was already analyzed
    chrome.storage.local.get([url], function(result) {
      if (result[url]) {
        // Use cached result
        displayResult(result[url]);
      } else {
        // Analyze URL
        analyzeUrl(url);
      }
    });
  });
  
  function analyzeUrl(url) {
    document.getElementById('loading').style.display = 'block';
    document.getElementById('result-container').style.display = 'none';
    document.getElementById('error').style.display = 'none';
    
    // Get API URL from settings
    chrome.storage.sync.get(['apiUrl'], function(items) {
      const apiUrl = items.apiUrl || 'http://localhost:8000/predict';
      
      fetch(`${apiUrl}?url=${encodeURIComponent(url)}`)
        .then(response => response.json())
        .then(data => {
          // Cache the result
          chrome.storage.local.set({[url]: data});
          displayResult(data);
        })
        .catch(error => {
          document.getElementById('loading').style.display = 'none';
          document.getElementById('error').style.display = 'block';
          document.getElementById('error').textContent = `Error: ${error.message}`;
        });
    });
  }
  
  function displayResult(data) {
    document.getElementById('loading').style.display = 'none';
    
    if (data.error) {
      document.getElementById('error').style.display = 'block';
      document.getElementById('error').textContent = data.error;
      return;
    }
    
    // Display result
    document.getElementById('result-container').style.display = 'block';
    const resultElement = document.getElementById('result');
    resultElement.textContent = data.result === 'Phishing' ? '🔴 Phishing' : '🟢 Legitimate';
    resultElement.className = `result ${data.result.toLowerCase()}`;
    
    // Display confidence
    if (data.confidence !== null) {
      document.getElementById('confidence').textContent = 
        `Confidence: ${(data.confidence * 100).toFixed(2)}%`;
    }
    
    // Check if site is blocked
    chrome.storage.sync.get(['autoBlock'], function(items) {
      if (items.autoBlock && data.is_phishing) {
        document.getElementById('blocked').style.display = 'block';
      } else {
        document.getElementById('blocked').style.display = 'none';
      }
    });
    
    // Display features
    const featuresContainer = document.getElementById('features-container');
    featuresContainer.innerHTML = '';
    
    if (data.features) {
      for (const [category, features] of Object.entries(data.features)) {
        const categoryDiv = document.createElement('div');
        categoryDiv.className = 'feature-category';
        
        // Add icon based on category
        let icon = '';
        if (category === 'Security Indicators') icon = '🔒';
        else if (category === 'Content Indicators') icon = '📝';
        else if (category === 'Reputation Indicators') icon = '🌐';
        else if (category === 'Structural Indicators') icon = '🏗️';
        
        const heading = document.createElement('h3');
        heading.textContent = `${icon} ${category}`;
        categoryDiv.appendChild(heading);
        
        for (const [name, value] of Object.entries(features)) {
          const featureDiv = document.createElement('div');
          featureDiv.className = 'feature-item';
          
          const nameSpan = document.createElement('span');
          nameSpan.className = 'feature-name';
          nameSpan.textContent = name;
          featureDiv.appendChild(nameSpan);
          
          const valueSpan = document.createElement('span');
          valueSpan.className = 'feature-value';
          
          // Add appropriate class based on value
          if (String(value).includes('Yes ✓') || String(value).includes('Established')) {
            valueSpan.classList.add('feature-good');
          } else if (String(value).includes('Yes ⚠️') || String(value).includes('Very New')) {
            valueSpan.classList.add('feature-bad');
          } else {
            valueSpan.classList.add('feature-neutral');
          }
          
          valueSpan.textContent = value;
          featureDiv.appendChild(valueSpan);
          
          categoryDiv.appendChild(featureDiv);
        }
        
        featuresContainer.appendChild(categoryDiv);
      }
    }
  }
});