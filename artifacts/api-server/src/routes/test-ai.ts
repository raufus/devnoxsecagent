import { Router, type IRouter } from "express";
import OpenAI from "openai";

const router: IRouter = Router();

// List of free models to try in order (verified working models)
const FREE_MODELS = [
  "nvidia/nemotron-3-nano-30b-a3b:free", // Nvidia free model (verified working)
  "google/gemini-2.0-flash-exp:free",
  "meta-llama/llama-3.2-3b-instruct:free", 
  "qwen/qwen-2-7b-instruct:free",
  "nousresearch/hermes-3-llama-3.1-405b:free",
];

// Get the appropriate model based on provider
function getModel() {
  const baseURL = process.env["AI_INTEGRATIONS_OPENAI_BASE_URL"] || "";
  if (baseURL.includes("openrouter.ai")) {
    return FREE_MODELS[0]; // Return first model, will try others if fails
  }
  return "gpt-4o-mini";
}

router.get("/test-ai", async (req, res) => {
  try {
    const apiKey = process.env.AI_INTEGRATIONS_OPENAI_API_KEY;
    const baseURL = process.env.AI_INTEGRATIONS_OPENAI_BASE_URL;

    if (!apiKey || apiKey === "dummy") {
      return res.json({
        status: "error",
        message: "OpenAI API key not configured",
        configured: false,
      });
    }

    if (!baseURL) {
      return res.json({
        status: "error",
        message: "OpenAI base URL not configured",
        configured: false,
      });
    }

    // Detect provider
    const isOpenRouter = baseURL.includes("openrouter.ai");
    const provider = isOpenRouter ? "OpenRouter" : "OpenAI";

    // Test API call with fallback models
    const defaultHeaders = isOpenRouter ? {
      "HTTP-Referer": "https://devnoxsec.com",
      "X-Title": "DevNox Sec Agent"
    } : {};

    const openai = new OpenAI({ apiKey, baseURL, defaultHeaders });
    
    let lastError = null;
    let successModel = null;
    let message = "";

    // Try each model if using OpenRouter
    const modelsToTry = isOpenRouter ? FREE_MODELS : [getModel()];
    
    for (const model of modelsToTry) {
      try {
        const response = await openai.chat.completions.create({
          model,
          messages: [{ role: "user", content: "Say 'API key is working!' in one sentence." }],
          max_tokens: 50,
        });

        message = response.choices[0]?.message?.content || "";
        successModel = model;
        break; // Success, exit loop
      } catch (err: any) {
        lastError = err;
        continue; // Try next model
      }
    }

    if (successModel) {
      return res.json({
        status: "success",
        message: `${provider} API key is valid and working!`,
        configured: true,
        provider,
        model: successModel,
        testResponse: message,
      });
    } else {
      throw lastError || new Error("All models failed");
    }
  } catch (err: any) {
    return res.json({
      status: "error",
      message: err.message || "API test failed",
      configured: true,
      error: err.toString(),
    });
  }
});

export default router;
