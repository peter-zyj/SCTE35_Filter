#!/usr/bin/env python
import os,sys
import re,binascii

def NumTrans(high,low,AndTag):
    PID_high = ord(high) & AndTag
    PID_low = hex(ord(low))
    #PID = hex(int(PID_high,2)) + hex(int(PID_low,2)).split('x')[-1]
    PID = hex(PID_high) + PID_low.split('x')[-1]
    pid_int = int(PID,16)
    return PID,pid_int

def C33xombine(a,b,c,d,e,AndTag):
    L = hex(ord(b)).split('x')[-1] + hex(ord(c)).split('x')[-1] +hex(ord(d)).split('x')[-1] + hex(ord(e)).split('x')[-1]
    H = ord(a) & AndTag
    HL = '0x'+str(H)+L
    hl = int(HL,16)
    return HL,hl

def HexCombine(List,AndTag):
    print "TBD"

def SCTE35_execute(stream_pid_dict,f,loop_time):
    f.seek(0)
    SCTE35_list = {}
    real_tag = False
    for i in range(loop_time):
        start_offset = 0
        dataH = f.read(188)
        PID,pid_int = NumTrans(dataH[1],dataH[2],0b00011111)
        payload = ord(dataH[1]) >> 6  & 0b01    
        if payload == 1:
            start_offset = ord(dataH[4])+5
            #print "start_offset: ",start_offset
            #print "dataH[0~10]:",dataH[0] dataH[1] dataH[2] dataH[3] dataH[4] dataH[0~10] dataH[0~10]
            TABLE_ID = hex(ord(dataH[start_offset]))
            #print "table_id is: ",TABLE_ID
            #print "PID is: ",PID
            if PID in stream_pid_dict.keys() and TABLE_ID == "0xfc":
                print "Splice Key Information List:"
                real_tag = True
                #PL,pl = NumTrans(dataH[start_offset+7],dataH[start_offset+8],0b11111111)
                #PH,ph = NumTrans(dataH[start_offset+5],dataH[start_offset+6],0b11111111)                                    
                #PTIME,ptime = NumTrans(unichr(ph),unichr(pl),0b1111111111111111)
                #ptimeh = ord(dataH[start_offset+4]) & 0b00000001
                #
                #PTS_ADJUSTMENT,pts_adjustment = NumTrans(unichr(ptimeh),unichr(ptime),0b1)      #unichr(ptime) exceed the unichr range
                #
                PTS_ADJUSTMENT,pts_adjustment = C33xombine(dataH[start_offset+4],dataH[start_offset+5],dataH[start_offset+6],dataH[start_offset+7],dataH[start_offset+8],0b1)
                SEC_LEN,sec_length = NumTrans(dataH[start_offset+1],dataH[start_offset+2],0b00001111)
                SPLCMD_LEN,splicecmd_length = NumTrans(dataH[start_offset+11],dataH[start_offset+12],0b00001111)
                End_line = start_offset+13+splicecmd_length
                cmd_type = ord(dataH[start_offset+13])
                if cmd_type == 5:
                    index = start_offset+13+1
                    if index <= End_line:
                        L,l = NumTrans(dataH[index+2],dataH[index+3],0b11111111)
                        H,h = NumTrans(dataH[index],dataH[index+1],0b11111111)
                        SPLICE_EVENT_ID,splice_event_id = NumTrans(unichr(h),unichr(l),0b1111111111111111)
                        #print "SPLICE EVENT ID is: ",SPLICE_EVENT_ID
                        splice_event_cancel_indicator = (ord(dataH[index+4]) & 0b10000000) >> 7
                        if splice_event_cancel_indicator == 0:
                            out_of_network_indicator = (ord(dataH[index+5]) & 0b10000000) >> 7
                            program_splice_flag = (ord(dataH[index+5]) & 0b01000000) >> 6
                            duration_flag = (ord(dataH[index+5]) & 0b00100000) >> 5
                            splice_immediate_flag = (ord(dataH[index+5]) & 0b00010000) >> 4
                            index2 = index+6
                            if (program_splice_flag == 1) and (splice_immediate_flag == 0):
                                time_specified_flag = (ord(dataH[index+6]) & 0b10000000) >> 7
                                if time_specified_flag == 1:
                                    PTS_TIME,pts_time = C33xombine(dataH[index+6],dataH[index+7],dataH[index+8],dataH[index+9],dataH[index+10],0b1)
                                    #print "rough PTS_TIME is:",PTS_TIME
                                    index2 = index+6+5
                                else:
                                    print "no detail splice time,warning!!!"
                                    PTS_TIME = 0x0
                                    index2 = index+6+1
                            else:
                                print "no splice time information"
                                PTS_TIME = 0x0
                            #ingore the element handling of "program_splice_flag"
                            #duration handling
                            if duration_flag == 1:
                                DURATION,duration = C33xombine(dataH[index2],dataH[index2+1],dataH[index2+2],dataH[index2+3],dataH[index2+4],0b1)
                            else:
                                print "No duration information, maybe the splice-in!"
                                DURATION = 0x0
                            
                            print "\n\
                                   SPLICE_EVENT_ID::%s\n\
                                   PTS_ADJUSTMENT ::%s\n\
                                   PTS_TIME       ::%s\n\
                                   DURATION       ::%s\n\
                                   \n\
                                  " % (SPLICE_EVENT_ID,PTS_ADJUSTMENT,PTS_TIME,DURATION)
                            continue
                        else:
                            print "Cancel the Splice event %s's arrangement" % (SPLICE_EVENT_ID)
                    else:
                        print "Exceed the length limit or finished the PID analysis,QUIT at once!"
                        continue
                else:
                    print "no support other command now, need to improvement later, Sorry for the command %s" % (cmd_type)
                    continue
            else:
                continue
            
    if real_tag == False:
        print "This content don't have any SCTE-35 info in the payload except the PMT!"

def execute(file):
    f = open(file)
    f.seek(0)
    size = os.path.getsize(file)
    print "the size of the file is: ",size
    
    loop_time = size/188
    # seach the PAT
    PAT_Ignore = False
    PMT_Ignore = False
    pid_pmt = None
    stream_pid_dict = {}
    for i in range(loop_time):
        start_offset = 0
        dataH = f.read(188)
        PID,pid_int = NumTrans(dataH[1],dataH[2],0b00011111)
        payload = ord(dataH[1]) >> 6  & 0b01
        if payload == 1:
            start_offset = ord(dataH[4])+5

            table_id = ord(dataH[start_offset])

            if PAT_Ignore == False and pid_int == 0 and table_id == 0:
                T_LEN,total_length = NumTrans(dataH[start_offset+1],dataH[start_offset+2],0b00001111)
                #PAT handling
                if ord(dataH[start_offset+6])==ord(dataH[start_offset+7])==0:               
                    PROGRAM,program_number = NumTrans(dataH[start_offset+8],dataH[start_offset+9],0b11111111)
                    if program_number != 0:               
                        PID_PMT,pid_pmt = NumTrans(dataH[start_offset+10],dataH[start_offset+11],0b00011111)
                        print 'PMT PID == ',PID_PMT
                        PAT_Ignore = True
                        continue
                    else:
                        print "network PID not expected,QUIT at once!"
                        f.close()
                        sys.exit(0)
                else:
                    print "complicated PMT! QUIT at once!"
                    f.close()
                    sys.exit(0)
            #PMT handling
            if PMT_Ignore == False and pid_int == pid_pmt and table_id == 2:
                
                T_LEN,total_length = NumTrans(dataH[start_offset+1],dataH[start_offset+2],0b00001111)
                DES_LEN,des_len = NumTrans(dataH[start_offset+10],dataH[start_offset+11],0b00001111)
                index = start_offset+12+des_len
                while 1:
                    if index < total_length+8-4:
                        stream_type = hex(ord(dataH[index]))

                        PID_STREAM,pid_stream = NumTrans(dataH[index+1],dataH[index+2],0b00011111)
                        print "PID:: %s **** Stream type: %s" % (PID_STREAM,stream_type)
                        stream_pid_dict[PID_STREAM] = stream_type
                        ES_LEN,es_len = NumTrans(dataH[index+3],dataH[index+4],0b00001111)
                        index = index+4+es_len+1

                    else:   
                        print "Exceed the length limit or finished the PID search,QUIT at once!"
                        PMT_Ignore = True
                        break
                        
                break
    print "PMT and PAT analysis completed!!!"
   
    while 1:
        R = raw_input("Continue to analyse the SCTE-35?? Yes Or No ?\n")
        RY= re.compile("yes|y", re.IGNORECASE)
        RN= re.compile("no|n", re.IGNORECASE)
        
        if RY.match(R):
            SCTE35_execute(stream_pid_dict,f,loop_time)
            break
        elif RN.match(R):
            print "Thanks for the Comments and feedback to yijuznhu, BYE!!"
            f.close()
            break
        else:
            print "Input error !!! Retry!"
    return 1       
    print "None"    

def usage():
    print "usage: " + "[SYNTAX:] python " + "check-SCTE35.py " + "file"         
    sys.exit(1)

if __name__ == '__main__':
    numargs = len(sys.argv) - 1
    if numargs == 0:
        usage()    
    else:
        tag = 0
        action = ''
        file = sys.argv[1]
	print "Analysis is on going......."
        execute(file)
    
    sys.exit(1) 