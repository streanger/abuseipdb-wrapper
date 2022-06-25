
def justify(content, colors_column=None, grid=True, frame=False, enumerator=False, header=False, topbar='', newline='\n', delimiter=';', justsize=4):
    """
    (function comes from juster module from 2019 with a little modification)
    justify(content, colors_column=None, grid=True, frame=False, enumerator=False, header=False, topbar='', newline='\n', delimiter=';', justsize=4)
        convert text to justified
        parameters:
            content - text with newlines and delimiters, to be converted
                      from version 0.1.2 it also can be list(tuple) of lists(tuples)
            grid - True/False value, grid inside; default is True
            frame - True/False value, frame around; default is False
            enumerator - True/False value, will add enumerator column on the left
            header - True/False value, will extract first row from content as header
            topbar - str value. Topbar will be added on the top
            newline - newline symbol; default is '\n'
            delimiter - delimiter symbol; default is ';'
            justsize - justify size; default is 4

        justify(content, grid=True, frame=False, newline='\n', delimiter=';', justsize=4)
        
    TODO: modify function/update juster pypi package
    """
    
    content = [[str(item).strip() for item in row] for row in content]
    maxRow = len(max(content, key=len))
    content = [item + [""]*(maxRow-len(item)) for item in content]
    
    # ********* extract header from content *********
    if header:
        if enumerator:
            headerValue = ['No.'] + content[0]
        else:
            headerValue = content[0]
        content = content[1:]
        
    # ********* add enumerator *********
    if enumerator:
        rowsNumber = len(str(len(content)))
        content = [[str(key+1).zfill(rowsNumber)] + row for key, row in enumerate(content)]
        
    # ********* append header after enumeration *********
    if header:
        content.insert(0, headerValue)
        
    # ********* create transposed *********
    transposed = list(map(list, zip(*content)))
    
    # ********* making table *********
    # characters
    if grid:
        horSign = '|'
    else:
        horSign = ' '
    vertSign = ' '
    lineLen = [max([len(part) for part in item]) for item in transposed]
    
    # justify all columns in the same way
    justifiedParts = [[part.center(lineLen[key]+justsize, vertSign) for key, part in enumerate(item)] for item in content]
    justifiedColoredParts = [[colored(part, *colors_column[index]) for part in item] for index, item in enumerate(justifiedParts)]
    content = [horSign.join(item) for item in justifiedColoredParts]
    
    line = '+'.join(["-"*len(item) for item in justifiedParts[0]])      # with '+' in the cross
    if frame:
        edgeLine = line.join(['+']*2)                                                       # with crosses
        line = line.join(['+']*2)
        content = [item.join(['|']*2) for item in content]
    line = line.join(['\n']*2)
    
    if grid:
        out = line.join(content)
    else:
        out = "\n".join(content)
        
    if frame:
        out = '\n'.join([edgeLine, out, edgeLine])
        
    # ********* add topbar *********
    if not topbar:
        return out
    contentWidth = out.find('\n')
    if contentWidth > 2:
        line = '+' + "-"*(contentWidth-2) + '+'
        sentence = '+' + topbar[:contentWidth-2].upper().center(contentWidth-2, ' ') + '+'
        if frame:
            strTopbar= '\n'.join([line, sentence])
        else:
            strTopbar = '\n'.join([line, sentence, line])
        out = strTopbar + '\n' + out
    return out
    
    