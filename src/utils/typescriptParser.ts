import { parse as parseJsdocType } from "jsdoc-type-pratt-parser";
import ts from "typescript";

/**
 * Converts JSDoc AST → JSON schema, with typedef resolution.
 */
function jsdocTypeToSchema(node: any, typedefs: Record<string, any>): any {
  if (!node) return {};

  switch (node.type) {
    case "JsdocTypeObject":
      return {
        type: "object",
        properties: Object.fromEntries(
          node.elements.map((el: any) => [
            el.key,
            jsdocTypeToSchema(el.value, typedefs),
          ])
        ),
      };

    case "JsdocTypeName":
      // Lookup typedef if available
      const refName = node.value;
      if (typedefs[refName]) return typedefs[refName];
      return { $ref: `#/components/schemas/${refName}` };

    case "JsdocTypeUnion":
      return { enum: node.elements.map((e: any) => e.value) };

    case "JsdocTypeStringValue":
      return { type: "string", enum: [node.value] };

    case "JsdocTypeNumber":
      return { type: "number" };

    case "JsdocTypeString":
      return { type: "string" };

    case "JsdocTypeBoolean":
      return { type: "boolean" };

    case "JsdocTypeAny":
      return {};

    case "JsdocTypeArray":
      return {
        type: "array",
        items: jsdocTypeToSchema(node.element, typedefs),
      };

    case "JsdocTypeIntersection":
      // handle `{A & B}`
      return {
        allOf: node.elements.map((n: any) => jsdocTypeToSchema(n, typedefs)),
      };

    default:
      return {};
  }
}

function normalizeJsdocType(text: string): string {
  // Replace commas separating fields with semicolons inside object literals
  return text
    .replace(/,\s*(?=\w+:)/g, "; ") // a,b,c -> a; b; c
    .replace(/Object\.<([^,>]+),\s*([^>]+)>/g, "Record<$1, $2>"); // legacy JSDoc
}

/**
 * Parses a raw JS/TS string, extracts all typedefs + @returns, and resolves them.
 */
export function getReturnTypeFromJsdoc(
  rawSource: string,
  functionName: string
) {
  const sourceFile = ts.createSourceFile(
    "inline.js",
    normalizeJsdocType(rawSource),
    ts.ScriptTarget.ESNext,
    true,
    ts.ScriptKind.JS
  );

  const typedefs: Record<string, any> = {};
  let returnTypeAst: any = null;

  function visit(node: ts.Node) {
    // Collect typedefs
    if ((node as any).jsDoc?.length) {
      for (const doc of (node as any).jsDoc) {
        const tags = doc.tags ?? [];

        // @typedefs
        for (const tag of tags) {
          if (tag.tagName?.text === "typedef" && tag.typeExpression?.type) {
            const typeText = tag.typeExpression.type.getText(sourceFile);
            try {
              const parsed = parseJsdocType(typeText, "jsdoc");
              typedefs[tag.name?.text] = jsdocTypeToSchema(parsed, typedefs);
              console.log(`Parsed typedef ${tag.name?.text}`);
            } catch (e) {
              console.error(
                `Failed to parse JSDoc for typedef ${tag.name?.text}: ${e}`
              );
              continue;
            }
          }
        }

        // @returns
        for (const tag of tags) {
          if (
            (tag.tagName?.text === "returns" ||
              tag.tagName?.text === "return") &&
            ts.isFunctionDeclaration(node) &&
            node.name?.text === functionName
          ) {
            const raw = tag.typeExpression?.type?.getText(sourceFile);
            try {
              if (raw) returnTypeAst = parseJsdocType(raw, "jsdoc");
              console.log(`Parsed @returns for ${functionName}`);
            } catch (e) {
              console.error(`Failed to parse JSDoc for ${functionName}: ${e}`);
              continue;
            }
          }
        }
      }
    }
    ts.forEachChild(node, visit);
  }

  ts.forEachChild(sourceFile, visit);

  if (!returnTypeAst) return null;

  return jsdocTypeToSchema(returnTypeAst, typedefs);
}
