import io

class BufferedReader:
    def __init__(self, reader):
        self.reader = reader
        self.buffer = []

    def read(self, size=-1):
        if not self.buffer:
            self.buffer = self.reader.read(io.DEFAULT_BUFFER_SIZE)
        if size == -1:
            size = len(self.buffer)
        data = self.buffer[:size]
        self.buffer = self.buffer[size:]
        return data

    def readline(self):
        while True:
            line = self.reader.readline()
            if not line:
                return line
            if line.endswith('\n'):
                return line
            self.buffer.append(line)

    def close(self):
        self.reader.close()

