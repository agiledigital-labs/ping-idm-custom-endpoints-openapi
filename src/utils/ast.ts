import type { Expression } from "acorn";
import * as acorn from "acorn";
import * as walk from "acorn-walk";

const walkAstForTargetNode = (
  ast: acorn.Program,
  targetNodeId: string
): Expression | undefined => {
  let foundNode: Expression | undefined = undefined;
  walk.simple(ast, {
    VariableDeclarator(node) {
      if (node.id.type === "Identifier" && node.id.name === targetNodeId) {
        foundNode = node.init ?? undefined;
      }
    },
    AssignmentExpression(node) {
      if (node.left.type === "Identifier" && node.left.name === targetNodeId) {
        foundNode = node.right;
      }
    },
  });

  return foundNode;
};

export const rawScriptToObject = (code: string, targetNodeId: string) => {
  const ast = acorn.parse(code, {
    ecmaVersion: "latest",
    sourceType: "module",
  });

  const targetNode = walkAstForTargetNode(ast, targetNodeId);

  // Convert AST node value to JS object
  if (!targetNode) {
    console.error('⚠️  No variable named "apis" found.');
    process.exit(1);
  }

  return targetNode;
};

export const expressionToObject = (
  node: Expression
): Object | undefined | null => {
  switch (node.type) {
    case "ObjectExpression":
      return Object.fromEntries(
        node.properties.map((prop) => {
          if (prop.type === "Property") {
            const key =
              prop.key.type === "Identifier"
                ? prop.key.name
                : prop.key.type === "Literal"
                  ? String(prop.key.value)
                  : `[Unsupported key type: ${prop.key.type}]`;
            const value = expressionToObject(prop.value);
            return [key, value];
          } else {
            return [`[Unsupported property type: ${prop.type}]`, undefined];
          }
        })
      );
    case "ArrayExpression":
      return node.elements.map((element) => {
        if (element === null) return null;
        if (element.type === "SpreadElement") {
          return `[Unsupported element type: SpreadElement]`;
        }
        return expressionToObject(element);
      });
    case "Literal":
      return node.value;
    case "Identifier":
      return node.name;
    case "CallExpression":
      // Handle buildApiEndpoint(...)
      if (
        node.callee.type === "Identifier" &&
        node.callee.name === "buildApiEndpoint"
      ) {
        const arg = node.arguments[0];
        if (arg && arg.type === "ObjectExpression") {
          return expressionToObject(arg);
        }
      }
      return `[Unsupported node type: CallExpression]`;
    default:
      return `[Unsupported node type: ${node.type}]`;
  }
};
