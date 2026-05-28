/**
 * Run an async worker over `inputs` with at most `concurrency` running at once.
 * Results array order matches input order (NOT completion order). The worker
 * is responsible for catching its own errors — pLimitFetch does not catch.
 * If a worker rejects, the returned promise rejects but in-flight workers
 * continue to completion (no cancellation).
 */
export async function pLimitFetch<I, O>(
  inputs: I[],
  concurrency: number,
  worker: (input: I, index: number) => Promise<O>
): Promise<O[]> {
  const results = new Array<O>(inputs.length)
  let next = 0

  async function runOne(): Promise<void> {
    while (true) {
      const i = next++
      if (i >= inputs.length) return
      results[i] = await worker(inputs[i], i)
    }
  }

  const slots = Math.max(1, Math.min(concurrency, inputs.length))
  const runners = Array.from({ length: slots }, () => runOne())
  await Promise.all(runners)
  return results
}
