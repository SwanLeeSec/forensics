import logging
import time
import sys
import _pfish

if __name__ =='__main__':
    PFISH_VERSION='1.0'

    logging.basicConfig(filename='pFishLog.log', level=logging.DEBUG, format='%(asctime)s %(message)s')

    _pfish.ParseCommandLine()
   
    startTime = time.time()

    logging.info('Welcome to p-fish version' + PFISH_VERSION + '... New Scan Started')
    _pfish.DisplayMessage('Welcome to p-fish ... version' + PFISH_VERSION)

    logging.info('System:'+ sys.platform)
    logging.info('Version:'+ sys.version)

    filesProcessed = _pfish.WalkPath()

    endTime = time.time()
    duration = endTime - startTime
    logging.info('Files Processed:' + str(filesProcessed))
    logging.info('Elapsed Time:'+ str(duration) + 'seconds')
    logging.info('')
    logging.info('Program Terminated Normally')
    logging.info('')

    _pfish.DisplayMessage ("Program End")


