import pytest
import yaml

from argus.probe import load_probe


def probe_data():
    return {'id': 'indirect_sample', 'name': 'Sample', 'target_class': ['http-chat'],
            'attack_class': ['prompt-injection'], 'severity': 'medium',
            'prompts': ['Original sample.'],
            'indirect': [{'task': 'Read the sample.', 'material': 'Sample document.'}]}


def write_probe(tmp_path, data):
    path = tmp_path / 'sample.yaml'
    path.write_text(yaml.safe_dump(data))
    return path


def test_indirect_length_must_match_prompts(tmp_path):
    data = probe_data()
    data['indirect'] = []
    with pytest.raises(ValueError, match=str(tmp_path)):
        load_probe(write_probe(tmp_path, data))


@pytest.mark.parametrize('mode', ['sessions', 'conversation'])
def test_indirect_with_sessions_or_conversation_is_rejected(tmp_path, mode):
    data = probe_data()
    if mode == 'sessions':
        data['sessions'] = [data.pop('prompts')]
    else:
        data['conversation'] = True
    with pytest.raises(ValueError, match=str(tmp_path)):
        load_probe(write_probe(tmp_path, data))


@pytest.mark.parametrize('item', [None, {}, {'task': 'Read'}, {'task': '', 'material': 'x'},
                                     {'task': 'Read', 'material': ' '}, {'task': 1, 'material': 'x'},
                                     {'task': 'Read', 'material': 'x', 'extra': 'x'}])
def test_indirect_items_need_nonempty_task_and_material(tmp_path, item):
    data = probe_data()
    data['indirect'] = [item]
    with pytest.raises(ValueError, match=str(tmp_path)):
        load_probe(write_probe(tmp_path, data))


def test_probe_without_indirect_loads_unchanged(tmp_path):
    data = probe_data()
    data.pop('indirect')
    probe = load_probe(write_probe(tmp_path, data))
    assert probe.indirect == ()
    assert probe.prompts == ('Original sample.',)


B_CLASS_IDS = frozenset({
    'agents_md_npm_install',
    'ambient_persuasion_pasted_content',
    'ambient_persuasion_url_fetch',
    'encoded_payload_base64_link',
    'encoded_payload_hex_codeblock',
    'guardrail_log_noise',
    'guardrail_log_noise_control',
    'obfuscated_code_minified_js',
    'obfuscated_code_powershell_encoded',
    'owasp_05_upload_svg_xss_render',
    'syscard_confused_deputy',
    'unicode_invisible_smuggling',
    'garak_goodside_tag',
    'garak_latentinjection_latentinjectionfactsnippeteiffel',
    'garak_latentinjection_latentinjectionfactsnippeteiffelfull',
    'garak_latentinjection_latentinjectionfactsnippetlegal',
    'garak_latentinjection_latentinjectionfactsnippetlegalfull',
    'garak_latentinjection_latentinjectionreport',
    'garak_latentinjection_latentinjectionreportfull',
    'garak_latentinjection_latentinjectionresume',
    'garak_latentinjection_latentinjectionresumefull',
    'garak_latentinjection_latentinjectiontranslationenfr',
    'garak_latentinjection_latentinjectiontranslationenfrfull',
    'garak_latentinjection_latentinjectiontranslationenzh',
    'garak_latentinjection_latentinjectiontranslationenzhfull',
    'garak_latentinjection_latentjailbreak',
    'garak_latentinjection_latentjailbreakfull',
    'garak_latentinjection_latentwhois',
    'garak_promptinject_hijackhatehumans',
    'garak_promptinject_hijackhatehumansfull',
    'garak_promptinject_hijackkillhumans',
    'garak_promptinject_hijackkillhumansfull',
    'garak_promptinject_hijacklongprompt',
    'garak_promptinject_hijacklongpromptfull',
})

DEFAULT_TASK_PROBES = frozenset({
    "garak_latentinjection_latentinjectionreport",
    "garak_latentinjection_latentinjectionresume",
    "garak_latentinjection_latentinjectionreportfull",
    "garak_latentinjection_latentinjectionresumefull",
    "owasp_05_upload_svg_xss_render",
})


def test_b_class_probes_all_carry_indirect():
    from argus.api import PROBES_DIR
    from argus.probe import load_probe_library

    probes = load_probe_library(PROBES_DIR)
    actual_ids = {probe.id for probe in probes if probe.indirect}
    matches = actual_ids == B_CLASS_IDS
    assert matches, "built-in indirect probe IDs must match B class"
    prompt_count_matches = sum(len(probe.prompts) for probe in probes
                               if probe.id in B_CLASS_IDS) == 128
    assert prompt_count_matches, "B class must retain 128 original prompts"


def test_indirect_material_is_verbatim_part_of_prompt():
    from argus.api import PROBES_DIR
    from argus.probe import load_probe_library

    for probe in load_probe_library(PROBES_DIR):
        for index, item in enumerate(probe.indirect):
            prompt = probe.prompts[index]
            material_is_verbatim = item.material in prompt
            task_is_nonempty = bool(item.task.strip())
            material_is_whole = item.material == prompt
            assert material_is_verbatim, f"{probe.id}[{index}] material must be verbatim"
            assert task_is_nonempty, f"{probe.id}[{index}] task must be nonempty"
            if probe.id in DEFAULT_TASK_PROBES:
                assert material_is_whole, f"{probe.id}[{index}] material must be whole"
            else:
                assert not material_is_whole, f"{probe.id}[{index}] material must be separate"


def test_required_material_target_runs_33_library_probes():
    from argus import api
    from argus.probe import load_probe_library
    from argus.targets.custom_http import CustomHTTPSpec, CustomHTTPTarget
    from test_transport_engine import spec_dict

    data = spec_dict()
    data["version"] = 2
    data["request"]["body"]["json"]["document"] = {"context": "material"}
    target = CustomHTTPTarget(CustomHTTPSpec(transport=data))
    assert target.material_channel
    compatible_ids = set(api.compatible_probe_ids(target))
    indirect_ids = {probe.id for probe in load_probe_library(api.PROBES_DIR)
                    if probe.indirect and probe.id in compatible_ids}
    matches = indirect_ids == B_CLASS_IDS - {"owasp_05_upload_svg_xss_render"}
    assert matches, "required material custom_http must support 33 B-class probes"


def test_tag_only_variants_reuse_the_family_request_without_losing_codepoints():
    from argus.api import PROBES_DIR
    from argus.probe import load_probe_library

    probe = next(probe for probe in load_probe_library(PROBES_DIR)
                 if probe.id == "garak_goodside_tag")
    entries_present = len(probe.indirect) == 5
    assert entries_present, f"{probe.id} must supply five indirect entries"
    for index, offset in enumerate((15, 2, 15, 2, 15)):
        material_preserved = probe.indirect[index].material == probe.prompts[index][offset:]
        assert material_preserved, f"{probe.id}[{index}] must retain every tag codepoint"
        source_index = index - 1 if index in (1, 3) else index
        family_request_preserved = probe.indirect[index].task == probe.prompts[source_index][:15].strip()
        assert family_request_preserved, f"{probe.id}[{index}] must retain its family request"
