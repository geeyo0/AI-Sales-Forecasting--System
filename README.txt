AI-Based Sales Forecasting and Decision Support System

FOLDER STRUCTURE
ai-sales-frontend/
  index.html       Page content: login, dashboard, sales, forecast, recommendations, reports, settings
  css/
    style.css      Colors, fonts, spacing, layout, responsive rules
  js/
    script.js      Demo navigation, temporary sales rows, and sample charts
  README.txt      This guide

START
1. Extract the ZIP to your Desktop.
2. In VS Code, open the extracted ai-sales-frontend folder.
3. Double-click index.html in File Explorer to preview it in a browser.
4. Click Continue with sample data to explore the screens.
5. Edit a file, save, then refresh your browser.

HTML connects to CSS with:
<link rel="stylesheet" href="css/style.css">

HTML connects to JavaScript with:
<script src="js/script.js"></script>

No Python, Flask, Django, or XAMPP is required for this frontend lesson.
Google Fonts requires internet; fallback fonts work offline.
Keep the css and js folders beside index.html. Do not open index.html inside the ZIP.

WHAT IS A DEMO
Login accepts any input and does not authenticate accounts.
The application screen is a business-dashboard design, not an admin dashboard yet.
Admin and business access will be implemented later in the backend.
Sales entries exist only in browser memory and reset on reload.
Dashboard totals and forecasts are sample values, not linked to entered sales.
The loading animation does not train an AI model.
Import and export buttons are placeholders. Print opens browser printing.
Settings are not saved.
Inventory management and the admin screens will be designed in later lessons.

LEARNING ORDER
1. Understand the login HTML.
2. Learn its CSS colors, spacing, and layout.
3. Study the sidebar and dashboard cards.
4. Learn the sales form and table.
5. Understand JavaScript interactions.
6. Connect the finished frontend to Flask and the database.
