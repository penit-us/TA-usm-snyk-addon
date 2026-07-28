import import_declare_test

import sys

from splunklib import modularinput as smi
from snyk_audit_logs_helper import stream_events, validate_input


class SNYK_AUDIT_LOGS(smi.Script):
    def __init__(self):
        super(SNYK_AUDIT_LOGS, self).__init__()

    def get_scheme(self):
        scheme = smi.Scheme('snyk_audit_logs')
        scheme.description = 'snyk_audit_logs'
        scheme.use_external_validation = True
        scheme.streaming_mode_xml = True
        scheme.use_single_instance = False

        scheme.add_argument(
            smi.Argument(
                'name',
                title='Name',
                description='Name',
                required_on_create=True
            )
        )
        scheme.add_argument(
            smi.Argument(
                'account',
                required_on_create=True,
            )
        )
        scheme.add_argument(
            smi.Argument(
                'version',
                required_on_create=True,
            )
        )
        scheme.add_argument(
            smi.Argument(
                'updated_after',
                required_on_create=False,
            )
        )
        scheme.add_argument(
            smi.Argument(
                'page_limit',
                required_on_create=False,
            )
        )
        return scheme

    def validate_input(self, definition: smi.ValidationDefinition):
        return validate_input(definition)

    def stream_events(self, inputs: smi.InputDefinition, ew: smi.EventWriter):
        return stream_events(inputs, ew)


if __name__ == '__main__':
    exit_code = SNYK_AUDIT_LOGS().run(sys.argv)
    sys.exit(exit_code)