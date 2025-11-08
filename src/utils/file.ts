import fs from "fs";
import path from "path";

export const writeToFile = (absPath: string, fileName: string, data: string) => {
  const outputFilePath = path.join(
    path.dirname(absPath),
    `${path.basename(absPath, path.extname(absPath))}${fileName}`
  );
  fs.writeFileSync(outputFilePath, data, "utf-8");
};
