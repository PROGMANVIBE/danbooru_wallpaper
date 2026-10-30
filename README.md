# Danbooru Wallpaper Application
A standalone Windows app that streams Danbooru art, GIFs, and MP4 files (sound suppressed) to your desktop. Powered by an authenticated local proxy to bypass rate limits, it features a floating search widget with live tag autocomplete, bookmarks, smooth media caching, auto looping video, locally stored credentials, application logs, multi-monitor support, and tray controls.

# FEATURES

**Floating Desktop Search Bar**: A movable on-screen search box that lets you query Danbooru tags directly without opening a web browser.

**Free 2D Movement & Lock**: Drag the bar anywhere across your screens using the move handle (✥), or click the lock icon (🔓/🔒) to fix it into position.

**Live Tag Suggestions**: Automatically queries Danbooru as you type to display the top 5 matching tags along with their post counts.

**Multi-Monitor Support**: Automatically identifies all monitors and allows for individual display settings per monitor.

**Search Bookmarks**: Save frequently used searches and recall or delete them via a drop-down menu.

**Application Pause and Animation Pause**: Pause the whole application operations or just pause the displayed content at anytime. 

**Local Media Proxy (127.0.0.1:8088)**: Streams images through an internal HTTP proxy with valid Danbooru headers, preventing Cloudflare blocks and rate limits.

**Buffered & Shuffled Playback**: Pre-fetches batches of posts (images and gifs only) into memory, shuffles them randomly per page, and filters out video extensions to ensure smooth transitions. 

**System Tray Control**: Runs unobtrusively in the Windows taskbar tray with a custom cardboard box icon, allowing you to hide/show the search bar, update credentials, view logs, or exit cleanly.

**Aggregated Real-Time Logs**: A built-in, opaque diagnostic window that captures server events, image proxying, API queries, and errors without crowding the screen.

**Secure Credential Storage**: Automatically creates an AppData folder for the currently logged in user and saves credentials locally in config.json rather than hardcoding them into the application. This folder can be manually deleted at anytime and the application will recreate it the next time the wallpaper is run. 


# HOW TO USE THE PROGRAM

**Searching Tags**: Type any standard Danbooru tag combination into the search bar (the default search is: scenery no_humans order:score) and press Enter to queue the search. Highly suggested to have a paid account in order to have more search tags and API requests.

**Immediate Refresh**: Press Shift + Enter in the input field or click the refresh button (⟳) on the bar to immediately clear the image buffer, increment the search epoch, and fetch new images.

**Selecting Suggestions**: Use the Up and Down arrow keys to highlight a recommended tag from the suggestion list, then press Enter to insert it.

**Saving a Search**: Click the arrow button (▲) on the right side of the input field to open the saved searches menu, then click 💾 Save Current Search.

**Minimizing to Tray**: Click the vertical bar on the far-left edge of the search widget, press Escape when no menus are open, or right-click the system tray icon and select Show Search Bar to toggle visibility.

**Accessing Settings**: Right-click the cardboard box tray icon and select Settings to update your Danbooru Username, User ID, or API Key at any time. Settings also includes all display settings including monitor selection, and streaming options. 


# REQUIREMENTS

**Runtime Requirements**
Operating System: Windows 10 or Windows 11 (64-bit)
Internet Connection: Active broadband connection to communicate with Danbooru

**Build / Source Requirements (If running from source)**
Python: Version 3.10 or higher
Python Libraries: Listed in requirements.txt (pystray, Pillow, pyinstaller)


# INSTALLATION

Running from Precompiled Executable (.exe)
Download the release folder or compile the application using:

PowerShell
python -m PyInstaller --noconfirm --onefile --noconsole --name "DanbooruWallpaper" --add-data "index.html;." --add-data "project.json;." --hidden-import webview --hidden-import pystray --hidden-import PIL danbooru_service.py

Alternatively, you can change "--onefile" to "--onedir" to compile it with a full list of internals instead of just getting the executable. 

Launch danbooru_service.exe.


# HOW TO FIND YOUR DANBOORU USERNAME, USER ID, AND API KEY

An authenticated Danbooru account is required to generate API tokens and query the service without restrictive anonymous rate limits:
1. Log into your account on https://danbooru.donmai.us/.
2. Click on My Account.
3. Username: Your account name as displayed on your profile.
4. User ID: This is the first option on your account profile; it should be 6 digits long.

API Key:
1. Log into your account on https://danbooru.donmai.us/.
2. Click on My Account.
3. The last option will be API Key; click view.
4. If an API Key is already generated, copy it; otherwise, click Generate API Key (or View) and copy the generated alphanumeric key.
-------------------------------
# Your API key is like your password. Anyone who has it has full access to your account. Don't give your API key to apps or people you don't trust, and don't post your API key in public locations.

The application will encrypt your API key while at rest using the native Windows Data Protection API (DPAPI via CryptProtectData / CryptUnprotectData in ctypes) so only your logged-in Windows user account on that specific machine can decrypt it. The saved credentials and settings can be found in your AppData (C:\Users\<Current_User>\AppData\Roaming) if it needs to be deleted at any time. 

Enter these three values (Username, User ID, and API Key) into the program setup dialog when prompted.


# WHY IS THIS INFORMATION NEEDED?

Danbooru requires your USERNAME and API_KEY to authenticate API requests via HTTP Basic Auth—unlocking higher rate limits and bypassing Cloudflare bot-prevention blocks—while your USER_ID is mandated by Danbooru's API terms to compose an identified, compliant User-Agent string (DanbooruWallpaperEngine/1.0 (by <USERNAME>; user #<USER_ID>)) that keeps your IP from being blacklisted. Rather than hardcoding these credentials into the source code, the application stores them locally in an encrypted config.json file in the users APPDATA, loading them strictly into system memory on startup to dynamically sign outbound HTTPS requests.

More information on Danbooru's API requirements can be found on their help:api page: https://danbooru.donmai.us/wiki_pages/help:api


## APPLICATION LOGS GLOSSARY

This glossary explains every message that can appear in the Application Logs 
window, what triggers it, and whether it indicates normal operation or an error.


# NORMAL OPERATION LOGS (Green / Routine)


[SERVER] Service running on http://127.0.0.1:8088
- What it means: The local Python background service started successfully.
- When it happens: Only once, immediately when you launch the application.

[AUTH] Loaded credentials for user '<username>' (#<id>)
- What it means: The program successfully read your saved Danbooru username and API key from config.json and applied them.
- When it happens: Only once at startup (if you previously saved credentials).

[AUTH] Credentials updated for user '<username>'.
- What it means: You clicked the "Save" button in the Settings & Credentials window. The new login info is now active.
- When it happens: Whenever you update settings.

[API] Requesting Page <page_number> for tags: '<search_tags>'
- What it means: The Python program is actively contacting the Danbooru website to download a new page of up to 100 images.
- When it happens: Roughly every 2 to 3 minutes when the application runs low on images and needs a fresh batch from the internet.

[FETCH] Fetched and shuffled # of images (Page #) for '<search_tags>'.
- What it means: A success message! Python received the 100 images from Danbooru, threw away any videos/invalid files, leaving <N> valid images. It then shuffled them so they appear in a random order on your wallpaper.
- When it happens: Exactly 1 to 2 seconds after the [API] Requesting Page... log.

[SERVER] Client requested batch from /api
- What it means: The applicaiton asks Python for its next small batch of 50 images to display on screen.
- When it happens: Frequently (e.g., every 30-90 seconds). This does NOT mean Python is contacting the internet; it is just handing stored images from RAM to the wallpaper.

[PING] Client polled /epoch (# of times in last # of seconds)
- What it means: A heartbeat check. The application quietly asks Python every second, "Did the user change the search tags yet?" To avoid spamming the log window, Python groups these checks and prints this single summary line every 60 seconds.
- When it happens: Once every 60 seconds, as long as the wallpaper is running.

--------------------------------------------------------------------------------
# USER INTERACTION LOGS (Blue / Informational)


[SEARCH] Queued tags: '<search_tags>'
- What it means: You typed a search and pressed Enter. The program noted your new tags and will switch to them as soon as the current images finish playing out.
- When it happens: When you press Enter in the search bar.

[REFRESH] Immediate refresh triggered. Epoch: <E> | Tags: '<search_tags>'
- What it means: You clicked the ⟳ button (or pressed Shift+Enter). The program instantly wiped all old images off the screen and forced an immediate search for the new tags.
- When it happens: When you manually force a refresh.

[SEARCH] Saved query to bookmarks: '<search_tags>'
- What it means: You clicked "💾 Save Current Search" in the ▲ menu. The tags are now saved in your dropdown list permanently.

[SEARCH] Removed query from bookmarks: '<search_tags>'
- What it means: You clicked the small "-" button next to a saved search to delete it.

[UI] Search bar lock state set to: True / False
- What it means: You clicked the 🔓/🔒 button in the settings window. True means dragging is locked; False means you can drag the bar around.

[UI] Logs viewer opened.
- What it means: You opened this exact log window from the system tray menu.

[APP] Shutting down application...
- What it means: You clicked "Exit" in the system tray. The program is closing everything and shutting down safely.

--------------------------------------------------------------------------------
# ERROR & WARNING LOGS (Red / Yellow)


[ERROR] No posts found for '<search_tags>'. Backing off <N>s...
- What it means: You searched for a tag combination that has exactly 0 results on Danbooru, or you made a typo. The program will pause for <N> seconds before letting you try again to prevent spamming the site.
- Action needed: Check your spelling or use fewer tags.

[ERROR] Fetch error: HTTP Error 401: Unauthorized. Backing off <N>s...
- What it means: Danbooru rejected your API Key or Username.
- Action needed: Open Settings (right-click the tray icon) and check your login info.

[ERROR] Fetch error: HTTP Error 429: Too Many Requests. Backing off <N>s...
- What it means: You requested too many pages too quickly, and Danbooru's servers temporarily timed you out.
- Action needed: Do nothing. The script will wait automatically (exponential backoff) and try again when the timeout lifts.

[ERROR] Fetch error: Danbooru error: You cannot search for more than 2 tags...
- What it means: Free/unregistered Danbooru accounts can only search 2 tags at once. You searched for 3 or more without being logged in (or with an invalid login).
- Action needed: Reduce your tags to 2 words, or enter your API key in Settings.

[FETCH] Multiple pages returned 0 usable images for '<tags>'. Cooling down 10s.
- What it means: Danbooru found results, but they were all videos, unsupported files, or images you already saw recently. After skipping multiple empty pages, the program paused for 10 seconds to avoid rapid-fire paging.
- Action needed: If this persists, the tag might only contain videos. Try a different tag.

[PROXY] Proxy stream dropped for https://... : <error details>
- What it means: While downloading a specific picture to display on the wallpaper, your internet connection blipped, or Danbooru's image server (CDN) timed out.
- Action needed: None. The wallpaper automatically discards the broken image and skips to the next one.

[SECURITY] Blocked unauthorized media host: <website>
- What it means: Something tried to use your local Python proxy to download an image from a website that isn't Danbooru.
- Action needed: None. The server blocked it automatically to protect your computer.

[SUGGEST] Suggestion fetch failed: <error details>
- What it means: While you were typing in the search bar, the background request to get autocomplete suggestions timed out.
- Action needed: None. The dropdown menu just won't appear for that word.

[CONFIG] Failed to load/save app config: <error details>
- What it means: The program couldn't read or write to config.json or saved_searches.json.
- Action needed: Ensure the folder where the .exe is located isn't read-only and that you aren't running it inside a zipped folder.
