# PixelAuth PIA driver for the [PinePhone Fingerprint Reader Addon Case](https://wiki.pine64.org/wiki/PinePhone_(Pro)_Add-ons#Fingerprint_Reader_Add-on)

### Note:
> This is a simple Python draft as of now.
> C driver for `libfprint` is a [work in progress](https://gitlab.freedesktop.org/libfprint/libfprint/-/issues/459).

Uses [SPI-to-I2C bridge](https://github.com/zschroeder6212/tiny-i2c-spi) by [@zschroeder6212](https://github.com/zschroeder6212) to communicate with the sensor.

### Usage example:
```shell
# modprobe i2c-dev
$ pip install -r requirements.txt
$ python pia.py
```
