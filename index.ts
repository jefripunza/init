import fs from "fs";
import path from "path";

import express from "express";
import cors from "cors";
import helmet from "helmet";
import morgan from "morgan";

const app = express();
app.use(cors());
app.use(helmet());
app.use(morgan("combined"));

// create ./script folder if not exist
if (!fs.existsSync(path.join(__dirname, "script"))) {
  fs.mkdirSync(path.join(__dirname, "script"));
}

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
  const userAgent = req.headers['user-agent'] || '';
  const isBrowser = userAgent.includes('Mozilla') || userAgent.includes('Chrome') || userAgent.includes('Safari') || userAgent.includes('Edge') || userAgent.includes('Firefox');
  
  if (isBrowser) {
    // For browser requests, show the example command
    // Extract the example command from the script content
    const exampleMatch = scriptContent.match(/# example: (.+)/i);
    const exampleCommand = exampleMatch ? exampleMatch[1] : `curl -fsSL https://init.jefripunza.com/${scriptName} | bash`;
    
    res.set('Content-Type', 'text/html');
    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>${scriptName} - Usage Example</title>
        <style>
          body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
          pre { background-color: #f4f4f4; padding: 15px; border-radius: 5px; overflow-x: auto; }
          h1 { color: #333; }
        </style>
      </head>
      <body>
        <h1>${scriptName}</h1>
        <p>To use this script, run the following command in your terminal:</p>
        <pre><code>${exampleCommand}</code></pre>
      </body>
      </html>
    `);
  } else {
    // For curl/wget requests, serve as downloadable bash file
    res.set('Content-Type', 'text/plain');
    res.set('Content-Disposition', `attachment; filename="${scriptName}"`);
    res.send(scriptContent);
  }
});

app.listen(3000, () => {
  console.log("Server is running on port 3000");
});
