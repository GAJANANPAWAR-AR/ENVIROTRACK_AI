// public/script.js

// --- Global Variables and Constants ---
let map;
let currentMarkers = {};
let userLocation = null;
let currentStream;
let capturedFile = null;
let currentReportId = null;

// Get user role and access token from browser's local storage (for municipal login)
let userRole = localStorage.getItem('userRole');
let accessToken = localStorage.getItem('accessToken');

const API_BASE_URL = '/api'; // This points to your Node.js backend API

// New global variable to store the heatmap layer
let heatLayer = null;

// --- DOM Elements (Declared with 'let', assigned inside DOMContentLoaded) ---
let mapDiv;
let showReportFormBtn;
let showLeaderboardBtn;
let showMunicipalLoginBtn;
let logoutBtn;

let reportFormContainer;
let wasteReportForm;
let wasteImageInput;
let cameraFeed;
let canvas;
let capturePhotoBtn;
let capturedImagePreview;
let descriptionInput;
let reportedByInput;
let latitudeInput;
let longitudeInput;
let getCurrentLocationBtn;

let reportDetailsPopup;
let popupDescription;
let popupReportedBy;
let popupReportedAt;
let popupLatitude;
let popupLongitude;
let popupWasteImage;
let municipalControls;
let cleanReportForm;
let cleanReportIdInput;
let cleanedImageInput;
let cleanedDetails;
let popupCleanedBy;
let popupCleanedAt;
let popupCleanedImage;

let municipalLoginFormContainer;
let municipalLoginForm;
let loginUsernameInput;
let loginPasswordInput;

let leaderboardContainer;
let leaderboardTableBody;


// --- Utility Functions ---

// Hides all overlay forms
function hideAllForms() {
    // Added checks if elements exist before trying to access .style
    if (reportFormContainer) reportFormContainer.style.display = 'none';
    if (reportDetailsPopup) reportDetailsPopup.style.display = 'none';
    if (municipalLoginFormContainer) municipalLoginFormContainer.style.display = 'none';
    if (leaderboardContainer) leaderboardContainer.style.display = 'none';
    stopCamera(); // Ensure camera is stopped when forms are hidden
}

// Helper to show a DOM element
function showElement(element) {
    if (element) element.style.display = 'block';
}

// Helper to hide a DOM element
function hideElement(element) {
    if (element) element.style.display = 'none';
}

// Updates the visibility of login/logout buttons based on user's authentication status
function updateAuthUI() {
    if (userRole === 'municipal' && accessToken) {
        hideElement(showMunicipalLoginBtn);
        showElement(logoutBtn);
    } else {
        showElement(showMunicipalLoginBtn);
        hideElement(logoutBtn);
    }
}

// --- Map Initialization and Interaction ---

function initializeMap() {
    // Initialize map centered on a general location (e.g., Hubballi, Karnataka, India) with a zoom level
    map = L.map('map').setView([15.3647, 75.1228], 13); // Latitude, Longitude, Zoom Level (Hubballi)

    // Add OpenStreetMap tiles to the map (free to use)
    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
        maxZoom: 19, // Max zoom level for these tiles
        attribution: '&copy; <a href="http://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
    }).addTo(map);

    // Try to get user's current location and center the map there
    map.locate({ setView: true, maxZoom: 16, enableHighAccuracy: true });

    // Event listener for when user's location is found
    map.on('locationfound', function(e) {
        userLocation = e.latlng; // Store location as a Leaflet LatLng object
        if (latitudeInput) latitudeInput.value = userLocation.lat.toFixed(6); // Populate latitude input
        if (longitudeInput) longitudeInput.value = userLocation.lng.toFixed(6); // Populate longitude input

        // Add a marker for the user's current location
        L.marker(userLocation)
            .addTo(map)
            .bindPopup("You are here!") // Popup text
            .openPopup(); // Show the popup
    });

    // Event listener for when location access fails
    map.on('locationerror', function(e) {
        console.error("Location access denied or error:", e.message);
        alert("Location access denied or error: " + e.message + ". Please enable location services or enter coordinates manually.");
    });

    fetchWasteReports(); // Load existing waste reports on the map when it loads
}

// Fetches active waste reports from the backend
async function fetchWasteReports() {
    try {
        const response = await fetch(`${API_BASE_URL}/waste-reports`);
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        const reports = await response.json();
        renderWasteReportsOnMap(reports); // Display them on the map
    } catch (error) {
        console.error('Error fetching waste reports:', error);
        alert('Could not load waste reports.');
    }
}

// Renders fetched waste reports as a heatmap on the map
function renderWasteReportsOnMap(reports) {
    // Clear any existing heatmap layer
    if (heatLayer) {
        map.removeLayer(heatLayer);
    }
    // Also clear individual markers if they were used before (though with heatmap, usually not needed)
    Object.values(currentMarkers).forEach(marker => map.removeLayer(marker));
    currentMarkers = {}; // Reset the storage

    // Prepare data for the heatmap: an array of [latitude, longitude, intensity]
    const heatData = [];
    reports.forEach(report => {
        // Only include reports that are NOT cleaned in the heatmap
        if (!report.is_cleaned) {
            heatData.push([parseFloat(report.latitude), parseFloat(report.longitude), 1]); // 1 is the intensity
        }

        // Add clickable markers only for *active* (uncleand) reports
        if (!report.is_cleaned) {
            const marker = L.circleMarker([parseFloat(report.latitude), parseFloat(report.longitude)], {
                radius: 8,
                fillColor: "#ff0000", // Red color for waste
                color: "#000",
                weight: 1,
                opacity: 1,
                fillOpacity: 0.8
            }).addTo(map);

            marker.on('click', () => {
                showReportDetails(report.id);
            });
            currentMarkers[report.id] = marker; // Store marker by ID if needed for later removal/update
        } else {
            // Optionally, add a different marker for cleaned reports, or just don't display them
            // For now, they won't be on the heatmap or as individual clickable markers
        }
    });

    // Create a new heatmap layer
    heatLayer = L.heatLayer(heatData, {
        radius: 25,    // Radius of the heat circle (adjust as needed)
        blur: 15,      // Amount of blur (adjust as needed for smoother heat)
        maxZoom: 17,    // Max zoom level for which the heatmap is active
        gradient: {    // Customize colors (optional)
            0.4: 'blue',
            0.6: 'cyan',
            0.7: 'lime',
            0.8: 'yellow',
            1.0: 'red'
        }
    }).addTo(map);
}

// Shows a popup with detailed information about a specific waste report
async function showReportDetails(reportId) {
    hideAllForms(); // Hide any other open forms first
    try {
        const response = await fetch(`${API_BASE_URL}/waste-reports/${reportId}`);
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        const report = await response.json();

        currentReportId = report.id; // Save this ID for potential cleaning action

        // Populate the popup with report data
        if (popupDescription) popupDescription.textContent = report.description || 'No description provided.';
        if (popupReportedBy) popupReportedBy.textContent = report.reported_by || 'Anonymous';
        if (popupReportedAt) popupReportedAt.textContent = new Date(report.reported_at).toLocaleString(); // Format date
        if (popupLatitude) popupLatitude.textContent = report.latitude;
        if (popupLongitude) popupLongitude.textContent = report.longitude;
        if (popupWasteImage) {
            popupWasteImage.src = report.image_url;
            popupWasteImage.style.display = report.image_url ? 'block' : 'none'; // Show image if available
        }


        // Handle municipal controls visibility
        if (municipalControls) { // Check if element exists
            if (userRole === 'municipal') { // Only show if a municipal user is logged in
                showElement(municipalControls);
                if (cleanReportIdInput) cleanReportIdInput.value = report.id; // Set report ID for the cleaning form
                // If report is already cleaned, show cleaned details, hide clean form
                if (report.is_cleaned) {
                    hideElement(cleanReportForm);
                    showElement(cleanedDetails);
                    // For cleanedBy, you might want to fetch username from user ID
                    if (popupCleanedBy) popupCleanedBy.textContent = report.cleaned_by_user_id ? `User ID ${report.cleaned_by_user_id}` : 'N/A';
                    if (popupCleanedAt) popupCleanedAt.textContent = report.cleaned_at ? new Date(report.cleaned_at).toLocaleString() : 'N/A';
                    if (popupCleanedImage) {
                        popupCleanedImage.src = report.cleaned_image_url;
                        popupCleanedImage.style.display = report.cleaned_image_url ? 'block' : 'none';
                    }
                } else { // If not cleaned, show clean form, hide cleaned details
                    showElement(cleanReportForm);
                    hideElement(cleanedDetails);
                }
            } else { // If not municipal user, hide all municipal controls
                hideElement(municipalControls);
                hideElement(cleanReportForm);
                // Ensure cleaned details are shown if report is cleaned, even for non-municipal users
                if (report.is_cleaned) {
                    showElement(cleanedDetails);
                    if (popupCleanedBy) popupCleanedBy.textContent = report.cleaned_by_user_id ? `User ID ${report.cleaned_by_user_id}` : 'N/A';
                    if (popupCleanedAt) popupCleanedAt.textContent = report.cleaned_at ? new Date(report.cleaned_at).toLocaleString() : 'N/A';
                    if (popupCleanedImage) {
                        popupCleanedImage.src = report.cleaned_image_url;
                        popupCleanedImage.style.display = report.cleaned_image_url ? 'block' : 'none';
                    }
                } else {
                    hideElement(cleanedDetails);
                }
            }
        }


        showElement(reportDetailsPopup); // Finally show the popup
    } catch (error) {
        console.error('Error fetching report details:', error);
        alert('Could not load report details.');
    }
}


// --- Camera and Location Functions ---

// Starts the device camera and displays the feed
async function startCamera() {
    if (currentStream) { // If a stream is already active, stop it first
        stopCamera();
    }
    try {
        // Request video stream, preferring the environment (rear) camera
        const stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' } });
        if (cameraFeed) cameraFeed.srcObject = stream; // Connect stream to video element
        currentStream = stream; // Store stream for later stopping

        showElement(cameraFeed); // Show the video element
        hideElement(wasteImageInput); // Hide the file input
        showElement(capturePhotoBtn); // Show the capture button
        hideElement(capturedImagePreview); // Hide previous preview
        capturedFile = null; // Reset captured file
    } catch (err) {
        console.error('Error accessing camera:', err);
        alert('Could not access camera. Please allow camera access or upload from gallery.');
        hideElement(cameraFeed); // Hide camera feed if it fails
        showElement(wasteImageInput); // Show file input as fallback
        hideElement(capturePhotoBtn); // Hide capture button
    }
}

// Stops the active camera stream
function stopCamera() {
    if (currentStream) {
        currentStream.getTracks().forEach(track => track.stop()); // Stop all tracks
        if (cameraFeed) cameraFeed.srcObject = null; // Disconnect stream from video element
        currentStream = null;
        hideElement(cameraFeed);
        hideElement(capturePhotoBtn);
    }
}

// --- Form Submission Handlers ---

// Fetches leaderboard data from the backend
async function fetchLeaderboard() {
    try {
        const response = await fetch(`${API_BASE_URL}/leaderboard`);
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        const leaderboardData = await response.json();
        renderLeaderboard(leaderboardData); // Display the leaderboard
    } catch (error) {
        console.error('Error fetching leaderboard:', error);
        alert('Could not load leaderboard.');
    }
}

// Renders the leaderboard data into the HTML table
function renderLeaderboard(data) {
    if (leaderboardTableBody) { // Check if element exists
        leaderboardTableBody.innerHTML = ''; // Clear existing rows
        if (data.length === 0) {
            leaderboardTableBody.innerHTML = '<tr><td colspan="3">No reports yet to form a leaderboard.</td></tr>';
            return;
        }

        data.forEach((entry, index) => {
            const row = leaderboardTableBody.insertRow(); // Create a new table row
            row.insertCell(0).textContent = index + 1; // Rank (1-based index)
            row.insertCell(1).textContent = entry.reported_by || 'Anonymous'; // Reporter name
            row.insertCell(2).textContent = entry.total_points; // Total points
        });
    }
    showElement(leaderboardContainer); // Show the leaderboard container
}


// --- Event Listeners (Connect buttons to functions) ---
// These are attached inside DOMContentLoaded

// --- Initial Setup on Page Load ---
// This runs when the entire HTML document has been loaded and parsed.
document.addEventListener('DOMContentLoaded', () => {
    // --- DOM Elements (Assign references here, inside DOMContentLoaded) ---
    mapDiv = document.getElementById('map');
    showReportFormBtn = document.getElementById('showReportFormBtn');
    showLeaderboardBtn = document.getElementById('showLeaderboardBtn');
    showMunicipalLoginBtn = document.getElementById('showMunicipalLoginBtn');
    logoutBtn = document.getElementById('logoutBtn');

    reportFormContainer = document.getElementById('reportFormContainer');
    wasteReportForm = document.getElementById('wasteReportForm');
    wasteImageInput = document.getElementById('wasteImageInput');
    cameraFeed = document.getElementById('cameraFeed');
    canvas = document.getElementById('canvas');
    capturePhotoBtn = document.getElementById('capturePhotoBtn');
    capturedImagePreview = document.getElementById('capturedImagePreview');
    descriptionInput = document.getElementById('description');
    reportedByInput = document.getElementById('reportedBy');
    latitudeInput = document.getElementById('latitude');
    longitudeInput = document.getElementById('longitude');
    getCurrentLocationBtn = document.getElementById('getCurrentLocationBtn');

    reportDetailsPopup = document.getElementById('reportDetailsPopup');
    popupDescription = document.getElementById('popupDescription');
    popupReportedBy = document.getElementById('popupReportedBy');
    popupReportedAt = document.getElementById('popupReportedAt');
    popupLatitude = document.getElementById('popupLatitude');
    popupLongitude = document.getElementById('popupLongitude');
    popupWasteImage = document.getElementById('popupWasteImage');
    municipalControls = document.getElementById('municipalControls');
    cleanReportForm = document.getElementById('cleanReportForm');
    cleanReportIdInput = document.getElementById('cleanReportId');
    cleanedImageInput = document.getElementById('cleanedImageInput');
    cleanedDetails = document.getElementById('cleanedDetails');
    popupCleanedBy = document.getElementById('popupCleanedBy');
    popupCleanedAt = document.getElementById('popupCleanedAt');
    popupCleanedImage = document.getElementById('popupCleanedImage');

    municipalLoginFormContainer = document.getElementById('municipalLoginFormContainer');
    municipalLoginForm = document.getElementById('municipalLoginForm');
    loginUsernameInput = document.getElementById('loginUsername');
    loginPasswordInput = document.getElementById('loginPassword');

    leaderboardContainer = document.getElementById('leaderboardContainer');
    leaderboardTableBody = document.querySelector('#leaderboardTable tbody');


    // --- Event Listeners (Attach here, inside DOMContentLoaded) ---

    // Event listener for the "Capture Photo" button
    if (capturePhotoBtn) { // Added null check
        capturePhotoBtn.addEventListener('click', () => {
            canvas.width = cameraFeed.videoWidth;
            canvas.height = cameraFeed.videoHeight;
            canvas.getContext('2d').drawImage(cameraFeed, 0, 0, canvas.width, canvas.height);

            canvas.toBlob((blob) => {
                capturedFile = new File([blob], `waste-image-${Date.now()}.jpeg`, { type: 'image/jpeg' });
                capturedImagePreview.src = URL.createObjectURL(blob);
                showElement(capturedImagePreview);
                hideElement(cameraFeed);
                hideElement(capturePhotoBtn);
            }, 'image/jpeg');
        });
    }


    // Event listener for when a file is selected via the input (e.g., from gallery)
    if (wasteImageInput) { // Added null check
        wasteImageInput.addEventListener('change', (event) => {
            stopCamera();
            const file = event.target.files[0];
            if (file) {
                capturedFile = file;
                capturedImagePreview.src = URL.createObjectURL(file);
                showElement(capturedImagePreview);
            } else {
                hideElement(capturedImagePreview);
                capturedFile = null;
            }
        });
    }


    // Event listener for the "Get My Location" button
    if (getCurrentLocationBtn) { // Added null check
        getCurrentLocationBtn.addEventListener('click', () => {
            if (navigator.geolocation) {
                navigator.geolocation.getCurrentPosition(position => {
                    userLocation = {
                        lat: position.coords.latitude,
                        lng: position.coords.longitude
                    };
                    latitudeInput.value = userLocation.lat.toFixed(6);
                    longitudeInput.value = userLocation.lng.toFixed(6);
                    map.setView(userLocation, 16);
                }, (error) => {
                    console.error('Error getting location:', error);
                    alert('Unable to retrieve your location. Please ensure location services are enabled and allowed.');
                    userLocation = null;
                    latitudeInput.value = '';
                    longitudeInput.value = '';
                });
            } else {
                alert('Geolocation is not supported by your browser.');
                userLocation = null;
            }
        });
    }


    // Handles the submission of the waste report form
    if (wasteReportForm) { // Added null check
        wasteReportForm.addEventListener('submit', async (event) => {
            event.preventDefault();

            if (!capturedFile) {
                alert('Please capture an image or select one from your gallery.');
                return;
            }
            if (!latitudeInput.value || !longitudeInput.value) {
                alert('Please get your current location.');
                return;
            }

            const formData = new FormData();
            formData.append('wasteImage', capturedFile);
            formData.append('latitude', latitudeInput.value);
            formData.append('longitude', longitudeInput.value);
            formData.append('description', descriptionInput.value);
            formData.append('reportedBy', reportedByInput.value);

            try {
                const response = await fetch(`${API_BASE_URL}/report-waste`, {
                    method: 'POST',
                    body: formData,
                });

                if (!response.ok) {
                    const errorData = await response.json();
                    throw new Error(errorData.message || `HTTP error! status: ${response.status}`);
                }

                const result = await response.json();
                alert('Waste reported successfully!');
                console.log('Report success:', result);
                wasteReportForm.reset();
                capturedFile = null;
                hideElement(capturedImagePreview);
                stopCamera();
                hideAllForms();
                fetchWasteReports();
            } catch (error) {
                console.error('Error submitting waste report:', error);
                alert('Failed to submit waste report: ' + error.message);
            }
        });
    }


    // Handles municipal user login
    if (municipalLoginForm) { // Added null check
        municipalLoginForm.addEventListener('submit', async (event) => {
            event.preventDefault();
            const username = loginUsernameInput.value;
            const password = loginPasswordInput.value;

            try {
                const response = await fetch(`${API_BASE_URL}/login`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, password }),
                });

                if (!response.ok) {
                    const errorData = await response.json();
                    throw new Error(errorData.message || `HTTP error! status: ${response.status}`);
                }

                const result = await response.json();
                localStorage.setItem('accessToken', result.accessToken);
                localStorage.setItem('userRole', result.role);
                accessToken = result.accessToken;
                userRole = result.role;
                alert('Logged in as Municipal User!');
                hideAllForms();
                updateAuthUI();
                fetchWasteReports();
            } catch (error) {
                console.error('Login failed:', error);
                alert('Login failed: ' + error.message);
            }
        });
    }


    // Handles marking a report as cleaned by a municipal user
    if (cleanReportForm) { // Added null check
        cleanReportForm.addEventListener('submit', async (event) => {
            event.preventDefault();
            const reportId = cleanReportIdInput.value;
            const cleanedImage = cleanedImageInput.files[0];

            if (!cleanedImage) {
                alert('Please upload a photo of the cleaned area.');
                return;
            }
            if (!accessToken) {
                alert('You must be logged in to mark a report as cleaned.');
                return;
            }

            const formData = new FormData();
            formData.append('cleanedImage', cleanedImage);

            try {
                const response = await fetch(`${API_BASE_URL}/clean-report/${reportId}`, {
                    method: 'PUT',
                    headers: {
                        'Authorization': `Bearer ${accessToken}`
                    },
                    body: formData,
                });

                if (!response.ok) {
                    const errorData = await response.json();
                    throw new Error(errorData.message || `HTTP error! status: ${response.status}`);
                }

                const result = await response.json();
                alert('Area marked as cleaned successfully!');
                console.log('Clean success:', result);
                hideAllForms();
                fetchWasteReports();
            } catch (error) {
                console.error('Error marking report as cleaned:', error);
                alert('Failed to mark report as cleaned: ' + error.message);
            }
        });
    }


    // Show Report Waste Form button
    if (showReportFormBtn) { // Added null check
        showReportFormBtn.addEventListener('click', () => {
            hideAllForms();
            wasteReportForm.reset();
            capturedFile = null;
            hideElement(capturedImagePreview);
            latitudeInput.value = userLocation ? userLocation.lat.toFixed(6) : '';
            longitudeInput.value = userLocation ? userLocation.lng.toFixed(6) : '';
            showElement(reportFormContainer);
            startCamera();
        });
    }


    // Show Leaderboard button
    if (showLeaderboardBtn) { // Added null check
        showLeaderboardBtn.addEventListener('click', () => {
            hideAllForms();
            fetchLeaderboard();
        });
    }


    // Show Municipal Login button
    if (showMunicipalLoginBtn) { // Added null check
        showMunicipalLoginBtn.addEventListener('click', () => {
            hideAllForms();
            municipalLoginForm.reset();
            showElement(municipalLoginFormContainer);
        });
    }


    // Logout button
    if (logoutBtn) { // Added null check
        logoutBtn.addEventListener('click', () => {
            localStorage.removeItem('accessToken');
            localStorage.removeItem('userRole');
            accessToken = null;
            userRole = null;
            alert('Logged out successfully.');
            updateAuthUI();
            hideAllForms();
            fetchWasteReports();
        });
    }

    // Initialize map and update UI after DOM is loaded
    initializeMap();
    updateAuthUI();
});