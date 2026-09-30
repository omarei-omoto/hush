// A stand-in for your app: it reads its key from the environment, as real
// code does, and prints it — which is exactly what hush's redaction is for.
const key = process.env.DEMO_API_KEY;
const db = process.env.DATABASE_URL;
if (!key) {
  console.error("DEMO_API_KEY is not set — run this with: hush run -- node app.js");
  process.exit(1);
}
console.log("Calling the demo API with key " + key);
console.log("Connecting to " + db);
console.log("(The key reached the program. It did not reach your terminal.)");
