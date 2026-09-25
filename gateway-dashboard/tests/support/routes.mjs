// Loads Next route handlers outside Next: "@/x" resolves from the project root
// and extensionless imports get ".js", the two things Next's bundler adds.
import { register } from "node:module";
import { pathToFileURL } from "node:url";
import path from "node:path";

const root = path.resolve(import.meta.dirname, "..", "..");

register(
  "data:text/javascript," +
    encodeURIComponent(`
      import { existsSync } from "node:fs";
      import { fileURLToPath, pathToFileURL } from "node:url";
      const root = ${JSON.stringify(root)};
      export async function resolve(spec, ctx, next) {
        let target = spec.startsWith("@/") ? root + "/" + spec.slice(2) : null;
        if (!target && spec.startsWith(".") && ctx.parentURL?.startsWith("file:")) {
          target = fileURLToPath(new URL(spec, ctx.parentURL));
        }
        if (target && !existsSync(target) && existsSync(target + ".js")) target += ".js";
        return next(target ? pathToFileURL(target).href : spec, ctx);
      }
    `),
  pathToFileURL(import.meta.filename),
);

export const route = (name) => import(pathToFileURL(path.join(root, "app", "api", name, "route.js")).href);

export const post = (body) =>
  new Request("http://console/api", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: typeof body === "string" ? body : JSON.stringify(body),
  });

export const params = (value) => ({ params: Promise.resolve(value) });
