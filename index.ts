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

// /:script_name tampilkan data dari ./script dan content type nya di buat untuk bash file
app.get("/:script_name", (req, res) => {
  const scriptName = req.params.script_name;
  const scriptPath = path.join(__dirname, "script", scriptName);

  if (!fs.existsSync(scriptPath)) {
    res.status(404).send("Script not found");
    return;
  }

  const scriptContent = fs.readFileSync(scriptPath, "utf-8");
  res.set("Content-Type", "text/plain");
  res.send(scriptContent);
});

app.listen(3000, () => {
  console.log("Server is running on port 3000");
});
