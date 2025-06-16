import fs from "fs";
import path from "path";

import express from "express";
import cors from "cors";
import helmet from "helmet";
import morgan from "morgan";

const host = "https://init.jefripunza.com";

const app = express();
app.use(cors());
// Configure Helmet to allow inline scripts
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'"],
      },
    },
  })
);
app.use(morgan("combined"));

// create ./script folder if not exist
if (!fs.existsSync(path.join(__dirname, "script"))) {
  fs.mkdirSync(path.join(__dirname, "script"));
}

// Root route to display a nice HTML page listing all script files with their descriptions
app.get("/", (req, res) => {
  const scriptPath = path.join(__dirname, "script");
  const scriptList = fs.readdirSync(scriptPath);
  
  // Get description for each script file
  const scriptsWithDetails = scriptList.map(scriptName => {
    const filePath = path.join(scriptPath, scriptName);
    let description = "";
    
    try {
      const content = fs.readFileSync(filePath, "utf-8");
      const descMatch = content.match(/# description:\s*(.+)/i);
      description = descMatch && descMatch[1] ? descMatch[1] : "No description available";
    } catch (error) {
      console.error(`Error reading file ${scriptName}:`, error);
      description = "Error reading description";
    }
    
    return { scriptName, description };
  });
  
  // Send HTML response
  res.set("Content-Type", "text/html");
  res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Script Initialization Library</title>
      <style>
        :root {
          --primary-color: #3498db;
          --secondary-color: #2980b9;
          --background-color: #f8f9fa;
          --card-bg: #ffffff;
          --text-color: #333333;
          --border-color: #e0e0e0;
        }
        
        body {
          font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
          line-height: 1.6;
          color: var(--text-color);
          background-color: var(--background-color);
          margin: 0;
          padding: 20px;
        }
        
        .container {
          max-width: 1000px;
          margin: 0 auto;
          padding: 20px;
        }
        
        header {
          text-align: center;
          margin-bottom: 30px;
        }
        
        h1 {
          color: var(--primary-color);
          margin-bottom: 10px;
        }
        
        .subtitle {
          color: #666;
          font-size: 1.1rem;
          margin-bottom: 30px;
        }
        
        .scripts-grid {
          display: grid;
          grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
          gap: 20px;
        }
        
        .script-card {
          background-color: var(--card-bg);
          border-radius: 8px;
          box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
          padding: 20px;
          transition: transform 0.3s ease, box-shadow 0.3s ease;
          border: 1px solid var(--border-color);
        }
        
        .script-card:hover {
          transform: translateY(-5px);
          box-shadow: 0 10px 15px rgba(0, 0, 0, 0.1);
        }
        
        .script-name {
          color: var(--primary-color);
          font-size: 1.3rem;
          margin-bottom: 10px;
          font-weight: 600;
        }
        
        .script-description {
          color: #555;
          margin-bottom: 15px;
        }
        
        .script-link {
          display: inline-block;
          background-color: var(--primary-color);
          color: white;
          padding: 8px 16px;
          border-radius: 4px;
          text-decoration: none;
          font-weight: 500;
          transition: background-color 0.2s ease;
        }
        
        .script-link:hover {
          background-color: var(--secondary-color);
        }
        
        .copy-command {
          margin-top: 15px;
          background-color: #f5f5f5;
          padding: 10px;
          border-radius: 4px;
          font-family: monospace;
          position: relative;
          cursor: pointer;
          overflow: hidden;
          text-overflow: ellipsis;
          white-space: nowrap;
        }
        
        .copy-command:hover {
          background-color: #ebebeb;
        }
        
        .copy-command::after {
          content: "Click to copy";
          position: absolute;
          right: 10px;
          font-size: 0.8rem;
          color: #888;
          top: 50%;
          transform: translateY(-50%);
        }
        
        footer {
          text-align: center;
          margin-top: 40px;
          color: #666;
          font-size: 0.9rem;
        }
        
        @media (max-width: 768px) {
          .scripts-grid {
            grid-template-columns: 1fr;
          }
        }
      </style>
    </head>
    <body>
      <div class="container">
        <header>
          <h1>Script Initialization Library</h1>
          <p class="subtitle">One-click installation scripts for various project setups</p>
        </header>
        
        <div class="scripts-grid">
          ${scriptsWithDetails.map(script => `
            <div class="script-card">
              <div class="script-name">${script.scriptName}</div>
              <div class="script-description">${script.description}</div>
              <a href="/${script.scriptName}" class="script-link">View Command</a>
            </div>
          `).join('')}
        </div>
        
        <footer>
          &copy; ${new Date().getFullYear()} Script Initialization Library
        </footer>
      </div>
    </body>
    </html>
  `);
});

// /:script_name - if accessed from browser, show example command; if accessed from curl/wget, download as bash file
app.get("/:script_name", (req, res) => {
  const scriptName = req.params.script_name;
  const scriptPath = path.join(__dirname, "script", scriptName);

  if (!fs.existsSync(scriptPath)) {
    res.status(404).send("Script not found");
    return;
  }
  const scriptContent = fs.readFileSync(scriptPath, "utf-8");

  // Check if request is from a browser or curl/wget based on User-Agent
  const userAgent = req.headers["user-agent"] || "";
  const isBrowser =
    userAgent.includes("Mozilla") ||
    userAgent.includes("Chrome") ||
    userAgent.includes("Safari") ||
    userAgent.includes("Edge") ||
    userAgent.includes("Firefox");

  if (isBrowser) {
    // For browser requests, show the example command
    // Extract the example command from the script content
    const exampleMatch = scriptContent.match(/# example: (.+)/i);
    const exampleCommand = exampleMatch
      ? exampleMatch[1]
      : `curl -fsSL ${host}/${scriptName} | bash`;

    res.set("Content-Type", "text/html");
    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>${scriptName} - Usage Example</title>
        <style>
          body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
          pre { 
            background-color: #f4f4f4; 
            padding: 15px; 
            border-radius: 5px; 
            overflow-x: auto; 
            position: relative;
          }
          h1 { color: #333; }
          .copy-button {
            position: absolute;
            top: 10px;
            right: 10px;
            background: #fff;
            border: 1px solid #ddd;
            border-radius: 4px;
            padding: 5px;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            width: 30px;
            height: 30px;
            transition: all 0.2s ease;
          }
          .copy-button:hover {
            background: #f0f0f0;
          }
          .copy-button svg {
            width: 18px;
            height: 18px;
          }
          .command-container {
            position: relative;
          }
          .script-content-container {
            margin-top: 20px;
          }
          .script-content {
            white-space: pre;
            font-family: monospace;
            line-height: 1.5;
          }
          h2 {
            margin-top: 30px;
            color: #333;
            border-bottom: 1px solid #eee;
            padding-bottom: 8px;
          }
        </style>
      </head>
      <body>
        <h1>${scriptName}</h1>
        <p>To use this script, run the following command in your terminal:</p>
        <div class="command-container">
          <pre><code id="command-text">${exampleCommand}</code></pre>
          <button class="copy-button" id="copy-button" title="Copy to clipboard">
            <svg id="copy-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
              <path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"></path>
            </svg>
            <svg id="check-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="display: none;">
              <polyline points="20 6 9 17 4 12"></polyline>
            </svg>
          </button>
        </div>
        
        <h2>Script Content</h2>
        <div class="script-content-container">
          <pre><code class="script-content">${scriptContent.replace(/</g, '&lt;').replace(/>/g, '&gt;')}</code></pre>
        </div>

        <script>
          document.getElementById('copy-button').addEventListener('click', function() {
            const commandText = document.getElementById('command-text').textContent;
            navigator.clipboard.writeText(commandText).then(function() {
              // Show check icon
              document.getElementById('copy-icon').style.display = 'none';
              document.getElementById('check-icon').style.display = 'block';
              
              // Change back to copy icon after 2 seconds
              setTimeout(function() {
                document.getElementById('copy-icon').style.display = 'block';
                document.getElementById('check-icon').style.display = 'none';
              }, 2000);
            });
          });
        </script>
      </body>
      </html>
    `);
  } else {
    // For curl/wget requests, serve as downloadable bash file
    res.set("Content-Type", "text/plain");
    res.set("Content-Disposition", `attachment; filename="${scriptName}"`);
    res.send(scriptContent);
  }
});

app.listen(3000, () => {
  console.log("Server is running on port 3000");
});
