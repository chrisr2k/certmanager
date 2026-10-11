/** Triggers a browser save-as for text content, without ever putting the
 * content in a navigable URL (a raw <a href> to an API endpoint carries
 * no Authorization header — see the ACME key-bundle download bug this
 * was extracted from). Always fetch authenticated content via apiClient
 * first, then hand the resulting string to this. */
export function saveTextFile(filename: string, content: string, mimeType = 'application/x-pem-file') {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
