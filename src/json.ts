/**
 * JSON.parse for anything hush did not write itself: a vault or a project file
 * that arrived through git, a request from an agent or a tailnet peer, a
 * message from the relay, a page in the browser.
 *
 * It refuses a `__proto__` key anywhere in the document. JSON.parse makes such
 * a key an ordinary property, harmlessly; the harm comes later, when code
 * copies keys from the parsed object into another one with `obj[key] = …`, and
 * `obj["__proto__"] = …` replaces that object's prototype instead of adding a
 * property. No file or message hush reads has a reason to contain the key, so
 * it is refused at the door rather than defended against at every copy.
 */
export function parseJson(text: string): any {
  return JSON.parse(text, (key, value) => {
    if (key === "__proto__") throw new SyntaxError('a "__proto__" key is not allowed');
    return value;
  });
}
