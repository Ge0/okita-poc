"""Okita entry point."""
import click


@click.command(context_settings={'help_option_names': ['-h', '--help']})
@click.argument("binary")
def main(binary):
    """Generate some disassembly listing of some binary executable."""
    raise SystemExit(0)


if __name__ == "__main__":
    main()
