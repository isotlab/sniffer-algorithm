
import sqlite3
from datetime import datetime
import datetime as dtime
class Intent:
    def __init__(self, action, component, timestamp):
        self.action = action
        self.component = component
        self.timestamp = timestamp


class Model:

    def __init__(self):
        self.black_list = []
        self.white_list = []
        self.white_list_action = []

        self.connection = sqlite3.connect('sniffer_validate.db')
        self.cursor = self.connection.cursor()

        self.black_list.append('com.nyaruka.androidrelay/com.nyaruka.androidrelay.MainActivity')

        # Whitelist
        self.white_list_action.append('android.intent.action.DIAL')
        #self.white_list.append('com.android.mms/com.android.mms.ui.ConversationList')
        #self.white_list.append('com.google.android.apps.plus/com.google.android.apps.plus.phone.ConversationListActivity')


        self.SEARCH_THRESHOLD = 35 # A post intent threshold to measure vlaues and the whitelist of the
        self.AUTOMATED_THRESHOLD =  2.1 # A 1 second threshold for a malicious style response
        self.confidence = 0

    def __datetime(self, date_str):
        return datetime.strptime(date_str, '%Y-%m-%d %H:%M:%S:%f')

    def process_intent(self, intent_action, component, timestamp):
        self.confidence = 0
        #print intent_action, component, timestamp

        if(intent_action.strip() == 'android.provider.Telephony.SMS_SENT'):

            params = (timestamp, 'android.provider.Telephony.SMS_RECEIVED')


            ########################################################
            # 1. Check how far back our last receive is, then compare this to the current SEND
            ########################################################

            self.cursor.execute('SELECT * FROM activity where timestamp < ? AND action = ? ORDER BY timestamp DESC LIMIT 1', params)
            receive_row = self.cursor.fetchone()

            diff_seconds = 0

            if((receive_row is not None) and (type(receive_row[5]) is unicode)):
                time_diff = self.__datetime(receive_row[5]) - self.__datetime(timestamp)
                diff_seconds =  abs(time_diff.total_seconds())
            else:
                #print "Skipping no receive element found"
                return False

            #print diff_seconds
            ########################################################
            # 2. The time difference, does it imply an automated style response? Between the SMS_RECEIVE?
            ########################################################
            rows = []
            if(diff_seconds < self.AUTOMATED_THRESHOLD):

                if((receive_row is not None) and (type(receive_row[5]) is unicode)):
                    params = (timestamp, receive_row[5])
                    rows = self.cursor.execute('SELECT * FROM activity where timestamp < ? AND timestamp > ?', params)

                    for row in rows:
                        #print "Checking component", row[3].strip()
                        if any(row[3].strip() in s for s in self.white_list):
                            #print "Adding as part of the WHITELIST"
                            self.confidence = -0.5

                params = (timestamp , self.__datetime(timestamp) + dtime.timedelta(0, self.SEARCH_THRESHOLD))
                #params = (self.__datetime(timestamp) - dtime.timedelta(0, self.SEARCH_THRESHOLD), self.__datetime(timestamp) + dtime.timedelta(0, self.SEARCH_THRESHOLD))
                rows = self.cursor.execute('SELECT * FROM activity where timestamp > ? AND timestamp < ?', params)

                for row in rows:
                    #print "Checking component", row[3].strip()
                    if any(row[3].strip() in s for s in self.white_list):
                        #print "Adding as part of the WHITELIST POST"
                        self.confidence = -0.5

                params = (self.__datetime(timestamp) - dtime.timedelta(0, self.SEARCH_THRESHOLD), self.__datetime(timestamp) + dtime.timedelta(0, self.SEARCH_THRESHOLD))
                rows = self.cursor.execute('SELECT * FROM activity where timestamp > ? AND timestamp < ?', params)

                for row in rows:
                    #print "Checking action", row[1].strip()
                    if any(row[1].strip() in s for s in self.white_list_action):
                        #print "Adding as part of the WHITELIST ACTIVITY RANGE"
                        self.confidence = -0.5





                #print "Adding as part of the AUTOMATED THRESHOLD"
                self.confidence += 0.5



            ########################################################
            # 3. Now check between last receive, and the send, do we have  a blacklisted value?
            ########################################################
            if((receive_row is not None) and (type(receive_row[5]) is unicode)):
                params = (timestamp, receive_row[5])
                rows = self.cursor.execute('SELECT * FROM activity where timestamp < ? AND timestamp > ?', params)
            for row in rows:
                if any(row[3].strip() in s for s in self.black_list):
                    #print "Adding as part of the BLACKLIST"
                    self.confidence += 1


            ########################################################
            # 4. Decision Time....
            ########################################################
            if(self.confidence >= 0.5):
                #print "returning TRUE"
                return True

        #print "returning FALSE"
        return False
