// Display the blocked URL
document.addEventListener('DOMContentLoaded', function() {
  // Get URL from query parameters
  const urlParams = new URLSearchParams(window.location.search);
  const blockedUrl = urlParams.get('url') || 'Unknown URL';
  document.getElementById('detected-url').textContent = blockedUrl;
  
  // Set up button actions
  document.getElementById('go-back').addEventListener('click', function() {
    window.history.back();
  });
  
  document.getElementById('proceed-anyway').addEventListener('click', function() {
    // Store this URL as temporarily allowed
    if (blockedUrl !== 'Unknown URL') {
      chrome.storage.local.get([blockedUrl], function(result) {
        if (result[blockedUrl]) {
          const data = result[blockedUrl];
          data.temporarily_allowed = true;
          chrome.storage.local.set({[blockedUrl]: data}, function() {
            window.location.href = blockedUrl;
          });
        } else {
          window.location.href = blockedUrl;
        }
      });
    }
  });
});