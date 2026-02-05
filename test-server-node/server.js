/**
 * Node.js/Express test API server for fuzzing.
 *
 * Intentional bugs for fuzzer validation:
 * - Type coercion issues (JS-specific)
 * - Missing null checks
 * - Prototype pollution
 * - Uncaught exceptions → 500
 * - Wrong Content-Type responses
 * - Schema-violating responses
 */

const express = require("express");
const app = express();
app.use(express.json());

// In-memory DB
const items = {
  1: { id: 1, name: "Widget", price: 9.99, stock: 100 },
  2: { id: 2, name: "Gadget", price: 24.5, stock: 50 },
  3: { id: 3, name: "Doohickey", price: 4.99, stock: 200 },
};
let nextId = 4;

// ─── Clean endpoints ───

app.get("/health", (_req, res) => {
  res.json({ status: "ok", uptime: process.uptime() });
});

app.get("/items", (_req, res) => {
  res.json({ items: Object.values(items), count: Object.keys(items).length });
});

app.get("/items/:id", (req, res) => {
  const id = Number(req.params.id);
  if (!items[id]) return res.status(404).json({ error: "Item not found" });
  res.json(items[id]);
});

// ─── Buggy endpoints ───

// Bug: JS type coercion — "0" is truthy, quantity*1 can be NaN
app.post("/orders", (req, res) => {
  const { product, quantity, discount } = req.body || {};
  if (!product) return res.status(422).json({ error: "product required" });

  // Bug 1: no parseInt → quantity could be string "abc" → NaN propagates
  const qty = quantity * 1;
  const price = 100;
  // Bug 2: discount not validated → can be negative or > 1
  const disc = discount || 0;
  const total = price * qty * (1 - disc);

  // Bug 3: NaN check missing — returns NaN in JSON
  res.json({ order_id: nextId++, total: total, quantity: qty });
});

// Bug: crashes on missing nested fields
app.put("/config", (req, res) => {
  const { theme, locale, features } = req.body || {};
  const result = {};

  // Bug: assumes theme.colors.primary exists
  if (theme) {
    result.primary_color = theme.colors.primary; // TypeError if colors is undefined
  }

  // Bug: locale.toUpperCase() crashes if locale is not a string
  if (locale) {
    result.locale = locale.toUpperCase();
  }

  // Bug: features.map crashes if features is not an array
  if (features) {
    result.enabled = features.map((f) => f.toLowerCase());
  }

  res.json({ updated: result });
});

// Bug: integer overflow / precision issues (JS Number)
app.get("/compute/:value", (req, res) => {
  const val = Number(req.params.value);

  // Bug 1: NaN check missing
  // Bug 2: Infinity not handled
  // Bug 3: precision loss for large integers
  const result = {
    squared: val * val,
    sqrt: Math.sqrt(val), // NaN for negative
    inverse: 1 / val, // Infinity for 0
    is_safe: Number.isSafeInteger(val),
  };

  // Bug: returns NaN/Infinity in JSON (invalid per JSON spec, but JS allows it)
  res.json(result);
});

// Bug: wrong Content-Type + schema-violating response
app.get("/report", (req, res) => {
  const format = req.query.format || "json";
  const year = Number(req.query.year) || 2024;

  if (format === "csv") {
    // Bug: returns text/csv when OpenAPI only declares application/json
    res.setHeader("Content-Type", "text/csv");
    res.send("id,name,value\n1,test,100\n");
    return;
  }

  if (format === "xml") {
    // Bug: returns text/xml
    res.setHeader("Content-Type", "text/xml");
    res.send("<report><year>" + year + "</year></report>");
    return;
  }

  // Bug: response doesn't match declared schema (missing required fields)
  if (year < 2000) {
    // Returns { error: "..." } instead of { year, data, generated_at }
    res.json({ error: "Year too old" });
    return;
  }

  res.json({
    year: year,
    data: [{ month: 1, revenue: 10000 }],
    generated_at: new Date().toISOString(),
  });
});

// Bug: regex DoS (ReDoS)
app.post("/validate", (req, res) => {
  const { email, pattern } = req.body || {};
  if (!email) return res.status(422).json({ error: "email required" });

  // Bug: user-supplied regex → ReDoS possible
  try {
    if (pattern) {
      const re = new RegExp(pattern); // can throw or hang
      if (!re.test(email)) {
        return res.status(422).json({ error: "pattern mismatch" });
      }
    }
  } catch (e) {
    // Bug: leaks internal error message
    return res.status(500).json({ error: e.message, stack: e.stack });
  }

  // Bug: naive email check — accepts "not-an-email"
  const valid = email.includes("@");
  res.json({ valid: valid, email: email });
});

// Bug: array index out of bounds
app.get("/users/:id/posts", (req, res) => {
  const page = Number(req.query.page) || 1;
  const limit = Number(req.query.limit) || 10;

  const allPosts = Array.from({ length: 25 }, (_, i) => ({
    id: i + 1,
    title: `Post ${i + 1}`,
    body: "Content here",
  }));

  // Bug 1: negative page → negative start
  // Bug 2: huge limit → memory issues
  // Bug 3: NaN propagation
  const start = (page - 1) * limit;
  const posts = allPosts.slice(start, start + limit);

  // Bug: returns wrong count type (string instead of number) for certain inputs
  const count = page < 0 ? "invalid" : posts.length;

  res.json({ posts: posts, count: count, page: page });
});

// Bug: prototype pollution risk
app.post("/merge", (req, res) => {
  const base = { role: "user", active: true };
  const input = req.body || {};

  // Bug: shallow merge without sanitizing __proto__ or constructor
  const merged = Object.assign({}, base, input);
  res.json(merged);
});

// Bug: uncaught async-style error
app.post("/process", (req, res) => {
  const { items: inputItems, operation } = req.body || {};

  if (!inputItems || !Array.isArray(inputItems)) {
    return res.status(422).json({ error: "items must be an array" });
  }

  // Bug 1: empty array → various crashes
  // Bug 2: non-numeric items → NaN
  const ops = {
    sum: (arr) => arr.reduce((a, b) => a + b, 0),
    avg: (arr) => arr.reduce((a, b) => a + b, 0) / arr.length,
    min: (arr) => Math.min(...arr), // Infinity on empty
    max: (arr) => Math.max(...arr), // -Infinity on empty
    product: (arr) => arr.reduce((a, b) => a * b, 1),
  };

  const fn = ops[operation];
  if (!fn) {
    // Bug: returns 200 with error message instead of 4xx
    return res.json({ error: "unknown operation", valid: Object.keys(ops) });
  }

  const result = fn(inputItems);
  res.json({ result: result, count: inputItems.length });
});

// ─── OpenAPI spec ───

app.get("/openapi.json", (_req, res) => {
  res.json({
    openapi: "3.1.0",
    info: { title: "Node Buggy API", version: "1.0.0" },
    paths: {
      "/health": {
        get: {
          responses: {
            200: {
              description: "Health check",
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      status: { type: "string" },
                      uptime: { type: "number" },
                    },
                    required: ["status", "uptime"],
                  },
                },
              },
            },
          },
        },
      },
      "/items": {
        get: {
          responses: {
            200: {
              description: "List items",
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      items: {
                        type: "array",
                        items: { $ref: "#/components/schemas/Item" },
                      },
                      count: { type: "integer" },
                    },
                    required: ["items", "count"],
                  },
                },
              },
            },
          },
        },
      },
      "/items/{id}": {
        get: {
          parameters: [
            {
              name: "id",
              in: "path",
              required: true,
              schema: { type: "integer" },
            },
          ],
          responses: {
            200: {
              description: "Item detail",
              content: {
                "application/json": {
                  schema: { $ref: "#/components/schemas/Item" },
                },
              },
            },
            404: { description: "Not found" },
          },
        },
      },
      "/orders": {
        post: {
          requestBody: {
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    product: { type: "string" },
                    quantity: { type: "integer", minimum: 1 },
                    discount: { type: "number", minimum: 0, maximum: 1 },
                  },
                  required: ["product", "quantity"],
                },
              },
            },
          },
          responses: {
            200: {
              description: "Order created",
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      order_id: { type: "integer" },
                      total: { type: "number" },
                      quantity: { type: "integer" },
                    },
                    required: ["order_id", "total", "quantity"],
                  },
                },
              },
            },
            422: { description: "Validation error" },
          },
        },
      },
      "/config": {
        put: {
          requestBody: {
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    theme: { type: "object" },
                    locale: { type: "string" },
                    features: {
                      type: "array",
                      items: { type: "string" },
                    },
                  },
                },
              },
            },
          },
          responses: {
            200: {
              description: "Config updated",
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      updated: { type: "object" },
                    },
                    required: ["updated"],
                  },
                },
              },
            },
          },
        },
      },
      "/compute/{value}": {
        get: {
          parameters: [
            {
              name: "value",
              in: "path",
              required: true,
              schema: { type: "integer" },
            },
          ],
          responses: {
            200: {
              description: "Computed values",
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      squared: { type: "number" },
                      sqrt: { type: "number" },
                      inverse: { type: "number" },
                      is_safe: { type: "boolean" },
                    },
                    required: ["squared", "sqrt", "inverse", "is_safe"],
                  },
                },
              },
            },
          },
        },
      },
      "/report": {
        get: {
          parameters: [
            { name: "format", in: "query", schema: { type: "string" } },
            { name: "year", in: "query", schema: { type: "integer" } },
          ],
          responses: {
            200: {
              description: "Report",
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      year: { type: "integer" },
                      data: { type: "array" },
                      generated_at: { type: "string", format: "date-time" },
                    },
                    required: ["year", "data", "generated_at"],
                  },
                },
              },
            },
          },
        },
      },
      "/validate": {
        post: {
          requestBody: {
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    email: { type: "string", format: "email" },
                    pattern: { type: "string" },
                  },
                  required: ["email"],
                },
              },
            },
          },
          responses: {
            200: {
              description: "Validation result",
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      valid: { type: "boolean" },
                      email: { type: "string" },
                    },
                    required: ["valid", "email"],
                  },
                },
              },
            },
            422: { description: "Validation error" },
          },
        },
      },
      "/users/{id}/posts": {
        get: {
          parameters: [
            {
              name: "id",
              in: "path",
              required: true,
              schema: { type: "integer" },
            },
            { name: "page", in: "query", schema: { type: "integer" } },
            { name: "limit", in: "query", schema: { type: "integer" } },
          ],
          responses: {
            200: {
              description: "User posts",
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      posts: { type: "array" },
                      count: { type: "integer" },
                      page: { type: "integer" },
                    },
                    required: ["posts", "count", "page"],
                  },
                },
              },
            },
          },
        },
      },
      "/merge": {
        post: {
          requestBody: {
            content: {
              "application/json": {
                schema: { type: "object" },
              },
            },
          },
          responses: {
            200: {
              description: "Merged object",
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      role: { type: "string" },
                      active: { type: "boolean" },
                    },
                    required: ["role", "active"],
                  },
                },
              },
            },
          },
        },
      },
      "/process": {
        post: {
          requestBody: {
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    items: {
                      type: "array",
                      items: { type: "number" },
                    },
                    operation: { type: "string", enum: ["sum", "avg", "min", "max", "product"] },
                  },
                  required: ["items", "operation"],
                },
              },
            },
          },
          responses: {
            200: {
              description: "Processing result",
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      result: { type: "number" },
                      count: { type: "integer" },
                    },
                    required: ["result", "count"],
                  },
                },
              },
            },
            422: { description: "Validation error" },
          },
        },
      },
    },
    components: {
      schemas: {
        Item: {
          type: "object",
          properties: {
            id: { type: "integer" },
            name: { type: "string" },
            price: { type: "number" },
            stock: { type: "integer" },
          },
          required: ["id", "name", "price", "stock"],
        },
      },
    },
  });
});

// Global error handler — catches unhandled errors as 500
app.use((err, _req, res, _next) => {
  console.error(err.stack);
  res.status(500).json({ error: "Internal Server Error", message: err.message });
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Node test server on http://localhost:${PORT}`);
  console.log(`OpenAPI spec: http://localhost:${PORT}/openapi.json`);
});
