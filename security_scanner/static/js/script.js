// ------------------------------------------------------------------
// SCRIPT.JS
// Main JavaScript file for the Frontend.
// Contains helper functions and logic for the website content.
// ------------------------------------------------------------------
// Main JavaScript file for Security Scanner

/**
 * Helper function to get the CSRF token from browser cookies.
 * Django requires this token for all POST requests to prevent Cross-Site Request Forgery.
 * @param {string} name - The name of the cookie (usually 'csrftoken')
 */

function getCookie(name) // Function to get a cookie value by name
{
    let cookieValue = null; // Initialize cookie value
    if (document.cookie && document.cookie !== '') // Check if cookies exist 
    {
        const cookies = document.cookie.split(';'); // Split cookies into an array
        for (let i = 0; i < cookies.length; i++) // Loop through cookies
        {
            const cookie = cookies[i].trim(); // Trim whitespace
            if (cookie.substring(0, name.length + 1) === (name + '=')) // Check if cookie name matches
            {
                cookieValue = decodeURIComponent(cookie.substring(name.length + 1)); // Get the cookie value
                break;
            }
        }
    }
    return cookieValue; // Return the cookie value
}

console.log('Security Scanner JS loaded'); // Log to console
