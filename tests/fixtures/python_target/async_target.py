import asyncio


async def call(prompt, material, context):
    await asyncio.sleep(0)
    return {"output": f"echo: {prompt} | material={material!r}"}
