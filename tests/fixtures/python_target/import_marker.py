import os

with open(os.environ["ARGUS_TEST_IMPORT_MARKER"], "w") as marker:
    marker.write("imported")


def call(prompt, material, context):
    return {"output": "marker target answered"}
