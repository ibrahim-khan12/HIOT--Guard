"""Frozen synthetic endpoint roles and session allocation for the fresh study."""
import random


ALLOCATION = {'train': ('A', 40), 'calibration': ('A', 10), 'validation': ('A', 10),
              'familiar': ('A', 10), 'transfer': ('B', 20)}
WINDOWS = (10, 30, 60, 120)
HL7 = {'infusion_pump': ('LAB_RATE', '99HIOT'), 'bedside_monitor': ('8867-4', 'LN'),
       'ecg_monitor': ('8867-4', 'LN'), 'lab_analyzer': ('GLUCOSE', '99HIOT'),
       'ventilator': ('9279-1', 'LN'), 'dialysis_machine': ('BLOOD_FLOW', '99HIOT')}
DICOM = {'ct': ('1.2.840.10008.5.1.4.1.1.2', 'CT'), 'mri': ('1.2.840.10008.5.1.4.1.1.4', 'MR'),
         'ultrasound': ('1.2.840.10008.5.1.4.1.1.6.1', 'US'), 'portable_xray': ('1.2.840.10008.5.1.4.1.1.1.1', 'DX')}
DICOM['fixed_xray'] = DICOM['portable_xray']
SUPPORT = ('fixed_xray', 'relay', 'workstation', 'ehr', 'pacs')
PROFILES = ('ordinary', 'batched', 'sparse', 'mixed')
LINK_PREFIX = {'upstream': 112, 'downstream': 113, 'direct': 114}
SOURCE_ROLES = tuple(HL7) + tuple(DICOM)


def address(link, session, suffix):
    return f'10.{LINK_PREFIX[link]}.{session["number"]}.{suffix}'


def sessions():
    number = 0
    for split, (stack, count) in ALLOCATION.items():
        for local_index in range(count):
            number += 1
            yield {'number': number, 'session_id': f'fresh-{number:03}', 'stack': stack, 'split': split,
                   'profile': PROFILES[local_index % len(PROFILES)], 'seed': 26112600 + number,
                   'capture_group': f'{split}-{local_index // 10 + 1:02}'}


def topology(session):
    rng = random.Random(session['seed'])
    suffixes = list(range(10, 50))
    rng.shuffle(suffixes)
    roles = SOURCE_ROLES + ('relay', 'workstation', 'ehr', 'pacs', 'auxiliary', 'end_marker')
    suffix = dict(zip(roles, suffixes))
    via = {role: ('upstream' if rng.choice((False, True)) else 'direct') for role in ('infusion_pump', 'ct')}
    return suffix, via


def endpoints(session):
    suffixes, via = topology(session)
    for role in SOURCE_ROLES + SUPPORT[1:]:
        link = via.get(role, 'downstream' if role in SUPPORT[1:] else 'direct')
        yield {'endpoint': address(link, session, suffixes[role]), 'role': role,
               'label': 'other' if role in SUPPORT else role, 'link': link}
